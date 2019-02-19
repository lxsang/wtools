

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
    printf("          Cell %02d - Address: %s\n", state->ap_num,
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
    iw_print_freq(buffer, sizeof(buffer),
                  freq, channel, event->u.freq.flags);
    printf("                    %s\n", buffer);
  }
  break;
  case SIOCGIWMODE:
    /* Note : event->u.mode is unsigned, no need to check <= 0 */
    if (event->u.mode >= IW_NUM_OPER_MODE)
      event->u.mode = IW_NUM_OPER_MODE;
    printf("                    Mode:%s\n",
           iw_operation_mode[event->u.mode]);
    break;
  case SIOCGIWNAME:
    printf("                    Protocol:%-1.16s\n", event->u.name);
    break;
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
        printf("                    ESSID:\"%s\" [%d]\n", essid,
               (event->u.essid.flags & IW_ENCODE_INDEX));
      else
        printf("                    ESSID:\"%s\"\n", essid);
    }
    else
      printf("                    ESSID:off/any/hidden\n");
  }
  break;
  
  case SIOCGIWRATE:
    if (state->val_index == 0)
      printf("                    Bit Rates:");
    else if ((state->val_index % 5) == 0)
      printf("\n                              ");
    else
      printf("; ");
    iw_print_bitrate(buffer, sizeof(buffer), event->u.bitrate.value);
    printf("%s", buffer);
    /* Check for termination */
    if (stream->value == NULL)
    {
      printf("\n");
      state->val_index = 0;
    }
    else
      state->val_index++;
    break;
  case IWEVQUAL:
    iw_print_stats(buffer, sizeof(buffer),
                   &event->u.qual, iw_range, has_range);
    printf("                    %s\n", buffer);
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

    printf("%-8.16s  Scan completed :\n", ifname);
    iw_init_event_stream(&stream, (char *)buffer, wrq.u.data.length);
    do
    {
      /* Extract an event and print it */
      ret = iw_extract_event_stream(&stream, &iwe,
                                    range.we_version_compiled);
      if (ret > 0)
        print_scanning_token(&stream, &iwe, &state,
                             &range, has_range);
    } while (ret > 0);
    printf("\n");
  }
  else
    printf("%-8.16s  No scan results\n\n", ifname);

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

  print_scanning_info(skfd, "wlo1", NULL, 0);

  /* Close the socket. */
  iw_sockets_close(skfd);

  return 0;
}
