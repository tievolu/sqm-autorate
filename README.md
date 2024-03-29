# sqm-autorate
A perl script to automatically adjust SQM rate limits on OpenWrt

# Basic installation instructions
(Hopefully I'll get round to writing an installation script at some point!)

1. `wget https://raw.githubusercontent.com/tievolu/sqm-autorate/main/sqm-autorate.pl`
2. `wget https://raw.githubusercontent.com/tievolu/sqm-autorate/main/sqm-autorate.conf`
3. `chmod 755 sqm-autorate.pl`
4. `opkg update; opkg install perl perlbase-attributes perlbase-filehandle perlbase-threads perlbase-time`
5. Edit `sqm-autorate.conf` and set the bandwidth / interface properties for your connection. You can also set the logfile location, but you'll need to handle rotation 6. using logrotate.
7. Download a list of ICMP type 13 reflectors from https://github.com/tievolu/timestamp-reflectors and update the `reflectors_csv_file` property in `sqm-autorate.conf` with its location. (You can of course create your own list of reflectors if you prefer.)
8. Run in the foreground: `./sqm-autorate.pl` or in the background: `(./sqm-autorate.pl >/dev/null 2>&1)&`

# Configuration Properties

```
Property name                   Default value                                     Units         Description
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
wan_interface                                                                                   Specifies the interface to use for WAN bandwidth usage measurements

ul_interface.[n]                                                                                Upload SQM interface names                         e.g. ul_interface.0 = eth0
dl_interface.[n]                                                                                Download SQM interface names                       e.g. dl_interface.0 = eth0

dl_bw_minimum                                                                     kilobits/s    Download SQM bandwidth will never be reduced below this value
dl_bw_standard                                                                    kilobits/s    Download SQM bandwidth will relax to this value when there is no significant bandwidth usage
dl_bw_maximum                                                                     kilobits/s    Download SQM bandwidth will never be increased above this value
dl_bw_warmup                    $dl_bw_minimum                                    kilobits/s    Download SQM bandwidth during adaptive ICMP warmup phase
ul_bw_minimum                                                                     kilobits/s    Upload SQM bandwidth will never be reduced below this value
ul_bw_standard                                                                    kilobits/s    Upload SQM bandwidth will relax to this value when there is no significant bandwidth usage
ul_bw_maximum                                                                     kilobits/s    Upload SQM bandwidth will never be increased above this value
ul_bw_warmup                    $ul_bw_minimum                                    kilobits/s    Upload SQM bandwidth during adaptive ICMP warmup phase
ul_bw_idle_threshold            $ul_bw_minimum                                    kilobits/s    If upload bandwidth is below this level, upload will be considered idle
dl_bw_idle_threshold            $dl_bw_minimum                                    kilobits/s    If download bandwidth is below this level, download will be considered idle

increase_factor                 1.0                                                             Used when calculating bandwidth increase steps. Higher value => larger increases
increase_min_pc                 1                                                 percent       Minimum percentage by which bandwidth can be increased
increase_max_pc                 25                                                percent       Maximum percentage by which bandwidth can be increased
increase_load_threshold         70                                                percent       Do not increase bandwidth if less than this proportion of the current bandwidth is being used
increase_delay_after_decrease   600                                               seconds       Do not increase bandwidth for this many seconds after a decrease
increase_delay_after_increase   0                                                 seconds       Do not increase bandwidth for this many seconds after an increase
decrease_delay_after_decrease   (icmp_interval_loaded * max_recent_results) + 1   seconds       Do not decrease bandwidth for this many seconds after a decrease
decrease_min_pc                 10                                                percent       Minimum percentage by which bandwidth can be decreased
decrease_overshoot_pc           5                                                 percent       When calculating decrease steps, the target bandwidth will be [average bad bandwidth] - decrease_overshoot_pc
relax_pc                        5                                                 percent       Percentage by which bandwidth is increased/decreased when relaxing towards the standard bandwidth
relax_load_threshold            50                                                percent       Do not relax bandwidth if more than this proportion of the current bandwidth is being used
relax_delay                     60                                                seconds       Do not relax bandwidth for at least this many seconds after any bandwidth change (including previous relax steps)

icmp_adaptive                   1                                                 boolean       If icmp_adaptive = 1 the ICMP interval will be set to icmp_interval_loaded or icmp_interval_idle according to connection load
icmp_interval_loaded            0.1                                               seconds       Interval between ICMP requests when connection is loaded (or if icmp_adaptive = 0)
icmp_interval_idle              1                                                 seconds       Interval between ICMP requests when connection is idle. icmp_interval_idle = 0 will disable pings completely when the connection is idle.
icmp_timeout                    1                                                 seconds       ICMP timeout
latency_check_interval          0.5                                               seconds       Interval between latency checks
max_recent_results              20                             Maximum number of recent ICMP results to consider when checking latency
bad_ping_pc                     25                                                percent       Proportion of bad ICMP results required to trigger a "bad" latency result
ul_max_idle_latency                                                               milliseconds  Maximum upload latency time with no bandwidth usage - see reflector_strikeout_threshold
ul_max_loaded_latency                                                             milliseconds  Maximum upload latency time with significant bandwidth usage
dl_max_idle_latency                                                               milliseconds  Maximum download latency time with no bandwidth usage - see reflector_strikeout_threshold
dl_max_loaded_latency                                                             milliseconds  Maximum download latency with significant bandwidth usage

reflectors_csv_file                                                                             CSV file containing the ICMP reflectors. The IP address must be in the first cell on each row. See https://github.com/tievolu/timestamp-reflectors
number_of_reflectors            30                                                              Number of reflectors to use
reflector_strikeout_threshold   3                                                               If a reflector performs poorly this many times within reflector_strike_ttl, we'll replace it (0 disables reflector strikes)
reflector_strike_ttl            auto                                                            Reflector strikes expire this many seconds after the associated ICMP response was received (or when it timed out). "auto" sets this to (number_of_reflectors / (1 / icmp_interval_[idle|loaded])) * (reflector_strikeout_threshold + 1).

tmp_folder                      /tmp                                                            Location for temporary files describing the most recent bandwidth change and time

log_file                                                                                        Log file path/name. If this is not set, logging to a file will be disabled. Note: Log rotation must be handled separately (e.g. with logrotate)
use_syslog                      1                                                 boolean       If use_syslog == 1, important messages will be sent to the syslog
latency_check_summary_interval  auto                                              seconds       Interval between summary latency check results output. 0 disables. "auto" sets this to max_recent_results * icmp_interval_[idle|loaded].
status_summary_interval         auto                                              seconds       Interval between status summaries. 0 disables. "auto" maintains this at latency_check_summary_interval * 30
log_bw_changes                  1                                                 boolean       Print information on bandwidth changes to the log. Automatically enabled if debug_bw_changes=1.
log_details_on_bw_changes       1                                                 boolean       When a bandwidth change occurs, print the latency results that triggered it. Automatically enabled if debug_bw_changes=1.

debug_icmp                      0                                                 boolean       Log debug information for each ICMP packet sent and received
debug_icmp_timeout              0                                                 boolean       Log debug information for ICMP requests that time out
debug_icmp_correction           0                                                 boolean       Log debug information when attempting to correct unusual ICMP timestamps. Automatically enabled if debug_icmp=1.
debug_icmp_suspend              0                                                 boolean       Log debug information when suspending and resuming the ICMP threads
debug_icmp_adaptive             0                                                 boolean       Log debug information when modifying the ICMP interval in response to connection load
debug_strike                    0                                                 boolean       Log debug information for getting/setting/checking reflector strikes
debug_latency_check             0                                                 boolean       Log debug information for every latency check
debug_sys_commands              0                                                 boolean       Log debug information when running system commands
debug_bw_changes                0                                                 boolean       Log debug information when changing bandwidth settings
debug_offsets                   0                                                 boolean       Log debug information when adjusting reflector offsets
```
