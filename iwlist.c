

#include "iwlib.h" /* Header */
#include <sys/time.h>

/****************************** TYPES ******************************/

/*
 * Scan state and meta-information, used to decode events...
 */
typedef struct iwscan_state
{
  /* State */
  int ap_num;    /* Access Point number 1->N */
  int val_index; /* Value in table 0->(N-1) */
} iwscan_state;



static void
iw_print_value_name(unsigned int value,
                    const char *names[],
                    const unsigned int num_names)
{
  if (value >= num_names)
    printf(" unknown (%d)", value);
  else
    printf(" %s", names[value]);
}

void
iw_print_json_stats(char *		buffer,
	       int		buflen,
	       const iwqual *	qual,
	       const iwrange *	range,
	       int		has_range)
{
  int		len;

  /* People are very often confused by the 8 bit arithmetic happening
   * here.
   * All the values here are encoded in a 8 bit integer. 8 bit integers
   * are either unsigned [0 ; 255], signed [-128 ; +127] or
   * negative [-255 ; 0].
   * Further, on 8 bits, 0x100 == 256 == 0.
   *
   * Relative/percent values are always encoded unsigned, between 0 and 255.
   * Absolute/dBm values are always encoded between -192 and 63.
   * (Note that up to version 28 of Wireless Tools, dBm used to be
   *  encoded always negative, between -256 and -1).
   *
   * How do we separate relative from absolute values ?
   * The old way is to use the range to do that. As of WE-19, we have
   * an explicit IW_QUAL_DBM flag in updated...
   * The range allow to specify the real min/max of the value. As the
   * range struct only specify one bound of the value, we assume that
   * the other bound is 0 (zero).
   * For relative values, range is [0 ; range->max].
   * For absolute values, range is [range->max ; 63].
   *
   * Let's take two example :
   * 1) value is 75%. qual->value = 75 ; range->max_qual.value = 100
   * 2) value is -54dBm. noise floor of the radio is -104dBm.
   *    qual->value = -54 = 202 ; range->max_qual.value = -104 = 152
   *
   * Jean II
   */

  /* Just do it...
   * The old way to detect dBm require both the range and a non-null
   * level (which confuse the test). The new way can deal with level of 0
   * because it does an explicit test on the flag. */
  if(has_range && ((qual->level != 0)
		   || (qual->updated & (IW_QUAL_DBM | IW_QUAL_RCPI))))
    {
      /* Deal with quality : always a relative value */
      if(!(qual->updated & IW_QUAL_QUAL_INVALID))
	{
	  len = snprintf(buffer, buflen, "\"quality\":%d,\n\"maxquality\":%d,\n",
			 qual->qual, range->max_qual.qual);
	  buffer += len;
	  buflen -= len;
	}

      /* Check if the statistics are in RCPI (IEEE 802.11k) */
      if(qual->updated & IW_QUAL_RCPI)
	{
	  /* Deal with signal level in RCPI */
	  /* RCPI = int{(Power in dBm +110)*2} for 0dbm > Power > -110dBm */
	  if(!(qual->updated & IW_QUAL_LEVEL_INVALID))
	    {
	      double	rcpilevel = (qual->level / 2.0) - 110.0;
	      len = snprintf(buffer, buflen, "\"signald\":%g,\n",
			     rcpilevel);
	      buffer += len;
	      buflen -= len;
	    }

	  /* Deal with noise level in dBm (absolute power measurement) */
	  if(!(qual->updated & IW_QUAL_NOISE_INVALID))
	    {
	      double	rcpinoise = (qual->noise / 2.0) - 110.0;
	      len = snprintf(buffer, buflen, "\"noised\":%g",
			     rcpinoise);
	    }
	}
      else
	{
	  /* Check if the statistics are in dBm */
	  if((qual->updated & IW_QUAL_DBM)
	     || (qual->level > range->max_qual.level))
	    {
	      /* Deal with signal level in dBm  (absolute power measurement) */
	      if(!(qual->updated & IW_QUAL_LEVEL_INVALID))
		{
		  int	dblevel = qual->level;
		  /* Implement a range for dBm [-192; 63] */
		  if(qual->level >= 64)
		    dblevel -= 0x100;
		  len = snprintf(buffer, buflen, "\"signald\":%d,\n",
				 dblevel);
		  buffer += len;
		  buflen -= len;
		}

	      /* Deal with noise level in dBm (absolute power measurement) */
	      if(!(qual->updated & IW_QUAL_NOISE_INVALID))
		{
		  int	dbnoise = qual->noise;
		  /* Implement a range for dBm [-192; 63] */
		  if(qual->noise >= 64)
		    dbnoise -= 0x100;
		  len = snprintf(buffer, buflen, "\"noised\":%d",
				 dbnoise);
		}
	    }
	  else
	    {
	      /* Deal with signal level as relative value (0 -> max) */
	      if(!(qual->updated & IW_QUAL_LEVEL_INVALID))
		{
		  len = snprintf(buffer, buflen, "\"signal\":%d,\n\"maxsignal\":%d,\n",
	
				 qual->level, range->max_qual.level);
		  buffer += len;
		  buflen -= len;
		}

	      /* Deal with noise level as relative value (0 -> max) */
	      if(!(qual->updated & IW_QUAL_NOISE_INVALID))
		{
		  len = snprintf(buffer, buflen, "\"noise\":%d,\n\"maxnoise\":%d,\n",
				 qual->noise, range->max_qual.noise);
		}
	    }
	}
    }
  else
    {
      /* We can't read the range, so we don't know... */
      /*snprintf(buffer, buflen,
	       "Quality:%d  Signal level:%d  Noise level:%d",
	       qual->qual, qual->level, qual->noise);*/
    }
}



/***************************** SCANNING *****************************/
/*
 * This one behave quite differently from the others
 *
 * Note that we don't use the scanning capability of iwlib (functions
 * iw_process_scan() and iw_scan()). The main reason is that
 * iw_process_scan() return only a subset of the scan data to the caller,
 * for example custom elements and bitrates are ommited. Here, we
 * do the complete job...
 */

/*------------------------------------------------------------------*/
/*
 * Print one element from the scanning results
 */
static inline void
print_scanning_token(struct stream_descr *stream, /* Stream of events */
                     struct iw_event *event,      /* Extracted token */
                     struct iwscan_state *state,
                     struct iw_range *iw_range, /* Range info */
                     int has_range)
{
  char buffer[128]; /* Temporary buffer */
  /* Now, let's decode the event */
  switch (event->cmd)
  {
  case SIOCGIWAP:
    printf("{\n\"cell\":%02d,\n\"address\": \"%s\",\n", state->ap_num,
           iw_saether_ntop(&event->u.ap_addr, buffer));
    state->ap_num++;
    break;
  /*case SIOCGIWNWID:
    if (event->u.nwid.disabled)
      printf("                    NWID:off/any\n");
    else
      printf("                    NWID:%X\n", event->u.nwid.value);
    break;*/
  case SIOCGIWFREQ:
  {
    double freq;      /* Frequency/channel */
    int channel = -1; /* Converted to channel */
    freq = iw_freq2float(&(event->u.freq));
    /* Convert to channel if possible */
    if (has_range)
      channel = iw_freq_to_channel(freq, iw_range);
    if(channel != -1)
    {
      printf("\"channel\":%d,\n", channel);
      printf("\"frequency\": %lf,\n", freq);
    }
    //iw_print_freq(buffer, sizeof(buffer),
    //              freq, channel, event->u.freq.flags);
    //printf("                    %s\n", buffer);
  }
  break;
  case SIOCGIWMODE:
    /* Note : event->u.mode is unsigned, no need to check <= 0 */
    if (event->u.mode >= IW_NUM_OPER_MODE)
      event->u.mode = IW_NUM_OPER_MODE;
    printf("\"mode\":%d,\n\"modename\":\"%s\",\n}\n",
           event->u.mode, iw_operation_mode[event->u.mode]);
    break;
  /*case SIOCGIWNAME:
    printf("                    Protocol:%-1.16s\n", event->u.name);
    break;*/
  case SIOCGIWESSID:
  {
    char essid[IW_ESSID_MAX_SIZE + 1];
    memset(essid, '\0', sizeof(essid));
    if ((event->u.essid.pointer) && (event->u.essid.length))
      memcpy(essid, event->u.essid.pointer, event->u.essid.length);
    if (event->u.essid.flags)
    {
      /* Does it have an ESSID index ? */
      if ((event->u.essid.flags & IW_ENCODE_INDEX) > 1)
        printf("\"ESSID\":\"'%s' [%d]\",\n", essid,
               (event->u.essid.flags & IW_ENCODE_INDEX));
      else
        printf("\"ESSID\":\"%s\",\n", essid);
    }
    else
      printf("\"ESSID\":\"off/any/hidden\",\n");
  }
  break;
  
  /*case SIOCGIWRATE:
    if (state->val_index == 0)
      printf("                    Bit Rates:");
    else if ((state->val_index % 5) == 0)
      printf("\n                              ");
    else
      printf("; ");
    iw_print_bitrate(buffer, sizeof(buffer), event->u.bitrate.value);
    printf("%s", buffer);
    if (stream->value == NULL)
    {
      printf("\n");
      state->val_index = 0;
    }
    else
      state->val_index++;
    break;
  */
  case IWEVQUAL:
    iw_print_json_stats(buffer, sizeof(buffer),
                   &event->u.qual, iw_range, has_range);
    printf("%s\n", buffer);
    break;
  /*case IWEVCUSTOM:
  {
    char custom[IW_CUSTOM_MAX + 1];
    if ((event->u.data.pointer) && (event->u.data.length))
      memcpy(custom, event->u.data.pointer, event->u.data.length);
    custom[event->u.data.length] = '\0';
    printf("                    Extra:%s\n", custom);
  }*/
  break;
  default:
  break;
  } /* switch(event->cmd) */
}

/*------------------------------------------------------------------*/
/*
 * Perform a scanning on one device
 */
static int
print_scanning_info(int skfd,
                    char *ifname,
                    char *args[], /* Command line args */
                    int count)    /* Args count */
{
  struct iwreq wrq;
  struct iw_scan_req scanopt;    /* Options for 'set' */
  int scanflags = 0;             /* Flags for scan */
  unsigned char *buffer = NULL;  /* Results */
  int buflen = IW_SCAN_MAX_DATA; /* Min for compat WE<17 */
  struct iw_range range;
  int has_range;
  struct timeval tv;      /* Select timeout */
  int timeout = 15000000; /* 15s */

  /* Avoid "Unused parameter" warning */
  args = args;
  count = count;

  /* Get range stuff */
  has_range = (iw_get_range_info(skfd, ifname, &range) >= 0);

  /* Check if the interface could support scanning. */
  if ((!has_range) || (range.we_version_compiled < 14))
  {
    fprintf(stderr, "%-8.16s  Interface doesn't support scanning.\n\n",
            ifname);
    return (-1);
  }

  /* Init timeout value -> 250ms between set and first get */
  tv.tv_sec = 0;
  tv.tv_usec = 250000;

  /* Clean up set args */
  memset(&scanopt, 0, sizeof(scanopt));

  wrq.u.data.pointer = NULL;
  wrq.u.data.flags = 0;
  wrq.u.data.length = 0;

  /* Initiate Scanning */
  if (iw_set_ext(skfd, ifname, SIOCSIWSCAN, &wrq) < 0)
  {
    if ((errno != EPERM) || (scanflags != 0))
    {
      fprintf(stderr, "%-8.16s  Interface doesn't support scanning : %s\n\n",
              ifname, strerror(errno));
      return (-1);
    }
    /* If we don't have the permission to initiate the scan, we may
	   * still have permission to read left-over results.
	   * But, don't wait !!! */
    tv.tv_usec = 0;
  }
  timeout -= tv.tv_usec;

  /* Forever */
  while (1)
  {
    fd_set rfds; /* File descriptors for select */
    int last_fd; /* Last fd */
    int ret;

    /* Guess what ? We must re-generate rfds each time */
    FD_ZERO(&rfds);
    last_fd = -1;

    /* In here, add the rtnetlink fd in the list */

    /* Wait until something happens */
    ret = select(last_fd + 1, &rfds, NULL, NULL, &tv);

    /* Check if there was an error */
    if (ret < 0)
    {
      if (errno == EAGAIN || errno == EINTR)
        continue;
      fprintf(stderr, "Unhandled signal - exiting...\n");
      return (-1);
    }

    /* Check if there was a timeout */
    if (ret == 0)
    {
      unsigned char *newbuf;

    realloc:
      /* (Re)allocate the buffer - realloc(NULL, len) == malloc(len) */
      newbuf = realloc(buffer, buflen);
      if (newbuf == NULL)
      {
        if (buffer)
          free(buffer);
        fprintf(stderr, "%s: Allocation failed\n", __FUNCTION__);
        return (-1);
      }
      buffer = newbuf;

      /* Try to read the results */
      wrq.u.data.pointer = buffer;
      wrq.u.data.flags = 0;
      wrq.u.data.length = buflen;
      if (iw_get_ext(skfd, ifname, SIOCGIWSCAN, &wrq) < 0)
      {
        /* Check if buffer was too small (WE-17 only) */
        if ((errno == E2BIG) && (range.we_version_compiled > 16))
        {
          /* Some driver may return very large scan results, either
		   * because there are many cells, or because they have many
		   * large elements in cells (like IWEVCUSTOM). Most will
		   * only need the regular sized buffer. We now use a dynamic
		   * allocation of the buffer to satisfy everybody. Of course,
		   * as we don't know in advance the size of the array, we try
		   * various increasing sizes. Jean II */

          /* Check if the driver gave us any hints. */
          if (wrq.u.data.length > buflen)
            buflen = wrq.u.data.length;
          else
            buflen *= 2;

          /* Try again */
          goto realloc;
        }

        /* Check if results not available yet */
        if (errno == EAGAIN)
        {
          /* Restart timer for only 100ms*/
          tv.tv_sec = 0;
          tv.tv_usec = 100000;
          timeout -= tv.tv_usec;
          if (timeout > 0)
            continue; /* Try again later */
        }

        /* Bad error */
        free(buffer);
        fprintf(stderr, "%-8.16s  Failed to read scan data : %s\n\n",
                ifname, strerror(errno));
        return (-2);
      }
      else
        /* We have the results, go to process them */
        break;
    }

    /* In here, check if event and event type
       * if scan event, read results. All errors bad & no reset timeout */
  }
 
  if (wrq.u.data.length)
  {
    struct iw_event iwe;
    struct stream_descr stream;
    struct iwscan_state state = {.ap_num = 1, .val_index = 0};
    int ret;

    //printf("%-8.16s  Scan completed :\n", ifname);
    iw_init_event_stream(&stream, (char *)buffer, wrq.u.data.length);
    do
    {
      /* Extract an event and print it */
      ret = iw_extract_event_stream(&stream, &iwe,
                                    range.we_version_compiled);
      if (ret > 0)
        {
          //printf("%s\n",",{");
          print_scanning_token(&stream, &iwe, &state,
                             &range, has_range);
           //printf("%s\n","}");
        }
    } while (ret > 0);
  }
  else
    printf("{\"error\": \"%-8.16s  No scan results\"}\n", ifname);
  free(buffer);
  return (0);
}

/******************************* MAIN ********************************/

/*------------------------------------------------------------------*/
/*
 * The main !
 */
int main(int argc,
         char **argv)
{
  int skfd; /* generic raw socket desc.	*/

  /* Create a channel to the NET kernel. */
  if ((skfd = iw_sockets_open()) < 0)
  {
    perror("socket");
    return -1;
  }

  print_scanning_info(skfd, "wlx6470021ccb6a", NULL, 0);

  /* Close the socket. */
  iw_sockets_close(skfd);

  return 0;
}
