#!/usr/bin/perl
#
# Introduction
# ============
#
# This script automatically adjusts the SQM bandwidth according to
# latency and load. It is designed to be run as a daemon / service.
#
# Bandwidth rests at a "standard" value, which should be a reasonable
# estimate of how much bandwidth capacity the WAN link can reliably
# deliver at most times. Bandwidth increases and decreases are
# limited by maxima and minima, and subject to various conditions
# (see below).
#
# Algorithm Outline
# =================
#
# Measure upload/download latency using a set of reflectors
#  |
#  |-> If latency is good
#  |    |-> If average load is greater than $increase_load_threshold_pc
#  |    |   '-> If the last increase/decrease occurred sufficiently
#  |    |       long ago (see $increase_delay_after_increase and 
#  |    |       $increase_delay_after_decrease)
#  |    |       '-> If at least $max_recent_results have been done
#  |    |           since the last bandwidth change
#  |    |           '-> If all recent pings were good
#  |    |               '-> If bandwidth is not at maximum
#  |    |                   '-> Increase the bandwidth
#  |    |
#  |    '-> If average load is less than $relax_load_threshold_pc
#  |        '-> If bandwidth is not at the standard bandwidth
#  |            |-> If the current bandwidth is less than the standard
#  |            |   bandwidth
#  |            |   '-> If the last increase/decrease occurred sufficiently
#  |            |       long ago (see $increase_delay_after_increase and
#  |            |       $increase_delay_after_decrease)
#  |            |       '-> If at least $max_recent_results have been done
#  |            |           since the last bandwidth change
#  |            |           '-> If all recent pings were good
#  |            |               '-> Relax the bandwidth
#  |            |
#  |            |-> If the last bandwidth change was an increase
#  |            |   '-> If the increase occurred sufficiently long ago
#  |            |       (see $increase_delay_after_increase and
#  |            |       $relax_delay)
#  |            |       '-> Relax the bandwidth
#  |            |                 
#  |            '-> If the last bandwidth change was a decrease
#  |                 '-> If the decrease occurred sufficiently long ago
#  |                     (see $increase_delay_after_decrease and
#  |                     $relax_delay)
#  |                     '-> Relax the bandwidth
#  |
#  '-> If latency is bad
#      '-> If internet connection is not completely down
#          '-> If load is greater than minimum bandwidth limit
#              '-> If bandwidth is not at minimum
#                  '-> Decrease the bandwidth
#
#
# Latency measurement
# ===================
#
# Upload and download latencies are measured separately using ICMP type
# 13 (timestamp) messages, so the target hosts ("reflectors") must
# respond to ICMP type 13 requests. Lists of reflectors for different
# regions can be downloaded from here:
# https://github.com/tievolu/timestamp-reflectors
#
# ICMP requests are sent on the ICMP Sender thread at regular intervals
# which, by default, are set according to load (see the "icmp_adaptive",
# "icmp_interval_idle", "icmp_interval_loaded", and
# "icmp_adaptive_idle_delay" properties), while the ICMP Receiver thread
# listens for responses. The results are stored in a shared array and
# the contents are periodically evaluated and acted upon on the main
# thread. See the "latency_check_interval" property.
#
# The targets for the ICMP messages, or "reflectors", are chosen at
# random from the CSV file specified in the "reflectors_csv" property.
#
# If a reflector performs poorly, it will be replaced with a new random
# reflector from the CSV file. Performing "poorly" means timing out too
# often, responding too slowly, or returning nonsensical ICMP timestamps. 
# This behaviour is controlled with the "reflector_strikeout_threshold",
# "reflector_strike_ttl", "ul_max_idle_latency", and "dl_max_idle_latency"
# properties. "reflector_strikeout_threshold" can be set to 0 to disable
# strikes completely and use a static set of reflectors. This is useful
# if you want to use a known good set of reflectors.
#
# Latency results are cleared after every bandwidth change.
#
# Bandwidth usage measurement
# ===========================
#
# Bandwidth usage is measured on the main thread every time we conduct a
# latency check. The average bandwidth usage between each latency check
# is stored, and when ICMP results are evaluated the bandwidth usage for
# the approprate time period is used to assess whether latency is likely
# to be caused by bufferbloat, which in turn determines if/how the SQM
# bandwidth should be changed (see algorithm description above).
#
# Bandwidth decreases
# ===================
#
# The logic behind the bandwidth decrease conditions shown above is that
# if there is no significant bandwidth usage, the bad pings are not
# caused by bufferbloat, and decreasing the bandwidth won't help. "Bad"
# pings that are not associated with significant bandwidth usage are
# ignored when evaluating latency.
#
# The amount by which the bandwidth is decreased is calculated based on
# the average bandwidth usage at the times when bad pings were detected.
# The bandwidth will be decreased to that average "bad" bandwidth usage
# plus a small "overshoot" controlled by the "decrease_overshoot_pc"
# property (default 5%).
#
# Bandwidth increases
# ===================
#
# Bandwidth will only be increased when we have a full set of clean
# ICMP results (i.e. no bad results). For example, if $max_recent_results
# is 20 and the ICMP interval is 0.1s, the minimum interval between
# bandwidth increases will be 2 seconds. Increases can be delayed further
# by adjusting the "increase_delay_after_decrease" and
# "increase_delay_after_increase" properties.
#
# The amount by which the bandwidth is increased is proportional to the
# the difference between the average good ping result and the "bad ping"
# threshold:
#
#   ([ping threshold] - [average good ping time]) * increase_factor
#
# The increase is also tapered as we approach the maximum bandwidth.
#
# Bandwidth relaxations
# =====================
#
# The SQM bandwidth will "relax" back to the standard bandwidth after any
# increases or decreases. The size of each relaxation step and the delay
# between them can be configured with the "relax_pc" and "relax_delay"
# properties. After a bandwidth decrease, relaxations will also be delayed
# by "increase_delay_after_decrease" to avoid an inappropriate increase
# after a relaxation.

use strict;
use warnings;

#######################################################################################
# Signal handlers
#######################################################################################

$SIG{INT}  = \&signal_handler;
$SIG{TERM} = \&signal_handler;

#######################################################################################
# Modules
#######################################################################################

use threads;
use threads::shared;
use POSIX qw(mktime strftime);
use Time::HiRes qw(gettimeofday);
use Time::Local qw(timegm);
use List::Util qw(shuffle min max sum);
use Socket qw(SOCK_RAW AF_INET MSG_DONTWAIT inet_ntoa inet_aton sockaddr_in pack_sockaddr_in unpack_sockaddr_in);

##################################################################################
# Constants
##################################################################################

# ICMP constants
use constant ICMP_PROTOCOL          => 1;
use constant ICMP_TIMESTAMP         => 13;
use constant ICMP_TIMESTAMP_REPLY   => 14;
use constant ICMP_TIMESTAMP_STRUCT  => "C2 n3 N3";  # Structure of a ICMP timestamp packet
use constant ICMP_PAYLOAD_OFFSET    => 20;

# Constants for latency results
use constant LATENCY_OK             =>  1;
use constant LATENCY_BAD            =>  2;
use constant LATENCY_BOTH_OK        =>  3;
use constant LATENCY_UL_BAD         =>  4;
use constant LATENCY_DL_BAD         =>  5;
use constant LATENCY_BOTH_BAD       =>  6;
use constant LATENCY_DOWN           => -1;
use constant LATENCY_INVALID        => -2;

# Special constants to use in place of genuine ICMP times
use constant ICMP_INVALID           => 88888;
use constant ICMP_TIMED_OUT         => 99999;

##################################################################################
# Shared global variables
##################################################################################

my $pid                    :shared;    # Process ID
my $cid                    :shared;    # Latency check cycle ID (incremented with each latency check)
my $output_lock            :shared;    # Controls access to output streams to avoid interleaving
my $suspend_icmp_sender    :shared;    # Tells the ICMP Sender thread to suspend/resume itself
my $suspend_icmp_receiver  :shared;    # Tells the ICMP Receiver thread to suspend/resume itself
my $sender_suspended       :shared;    # Indicates that the ICMP Sender thread is suspended
my $receiver_suspended     :shared;    # Indicates that the ICMP Receiver thread is suspended
my $icmp_interval          :shared;    # ICMP interval
my $icmp_request_count     :shared;
my $icmp_request_bytes     :shared;
my $icmp_response_count    :shared;
my $icmp_response_bytes    :shared;    
my %icmp_timeout_times     :shared;    # Time at which a pending ICMP request will time out
my %icmp_sent_times        :shared;    # Time at which an ICMP request was sent
my @recent_results         :shared;    # Recent ICMP results
my %reflector_ips          :shared;    # ICMP reflector IP addresses
my %reflector_packet_ids   :shared;    # Packet ID for each ICMP reflector
my %reflector_seqs         :shared;    # Current sequence ID for each ICMP reflector
my %reflector_offsets      :shared;    # Time offset for each ICMP reflector
my %reflector_minimum_rtts :shared;    # Minimum RTT time seen for each ICMP reflector (used when calculating the offset)

# Initialise the process ID and cycle ID
$pid = "$$";
$cid = sprintf("%010d", 0);

#######################################################################################
# Configuration
#######################################################################################

# Read the configuration properties file and use them to populate global variables
# Configuration file can be located in the same directory as the script, or /etc
my $config_file = substr($0, 0, rindex($0, "/")) . "/sqm-autorate.conf";
if (! -e $config_file) {
	$config_file = "/etc/sqm-autorate.conf";
}
my %config_properties = &get_config_properties($config_file);

# Upload interfaces
my $index = 0;
my @ul_interfaces = ();
while(
	exists($config_properties{"ul_interface." . $index})
) {
	my $if_name = $config_properties{"ul_interface." . $index};
	push(@ul_interfaces, $if_name);
	$index++
}

# Download interfaces
$index = 0;
my @dl_interfaces = ();
while(
	exists($config_properties{"dl_interface." . $index})
) {
	my $if_name = $config_properties{"dl_interface." . $index};
	push(@dl_interfaces, $if_name);
	$index++;
}

# Normal configuration properties with defaults
my $wan_interface                  = &get_config_property("wan_interface",                  undef);
my $dl_bw_minimum                  = &get_config_property("dl_bw_minimum",                  undef);
my $dl_bw_standard                 = &get_config_property("dl_bw_standard",                 undef);
my $dl_bw_maximum                  = &get_config_property("dl_bw_maximum",                  undef);
my $ul_bw_minimum                  = &get_config_property("ul_bw_minimum",                  undef);
my $ul_bw_standard                 = &get_config_property("ul_bw_standard",                 undef);
my $ul_bw_maximum                  = &get_config_property("ul_bw_maximum",                  undef);
my $increase_factor                = &get_config_property("increase_factor",                1);
my $increase_min_pc                = &get_config_property("increase_min_pc",                1);
my $increase_max_pc                = &get_config_property("increase_max_pc",                25);
my $increase_load_threshold_pc     = &get_config_property("increase_load_threshold_pc",     70);
my $increase_delay_after_decrease  = &get_config_property("increase_delay_after_decrease",  600);
my $increase_delay_after_increase  = &get_config_property("increase_delay_after_increase",  0);
my $decrease_min_pc                = &get_config_property("decrease_min_pc",                10);
my $decrease_overshoot_pc          = &get_config_property("decrease_overshoot_pc",          5);
my $relax_pc                       = &get_config_property("relax_pc",                       5);
my $relax_load_threshold_pc        = &get_config_property("relax_load_threshold_pc",        50);
my $relax_delay                    = &get_config_property("relax_delay",                    60);
my $icmp_adaptive                  = &get_config_property("icmp_adaptive",                  1);
my $icmp_adaptive_idle_delay       = &get_config_property("icmp_adaptive_idle_delay",       10);
my $icmp_interval_idle             = &get_config_property("icmp_interval_idle",             1);
my $icmp_interval_loaded           = &get_config_property("icmp_interval_loaded",           &get_config_property("icmp_interval", 0.1));
my $icmp_timeout                   = &get_config_property("icmp_timeout",                   1);
my $latency_check_interval         = &get_config_property("latency_check_interval",         0.5);
my $max_recent_results             = &get_config_property("max_recent_results",             20);
my $bad_ping_pc                    = &get_config_property("bad_ping_pc",                    25);
my $ul_max_loaded_latency          = &get_config_property("ul_max_loaded_latency",          undef);
my $ul_max_idle_latency            = &get_config_property("ul_max_idle_latency",            $ul_max_loaded_latency);
my $dl_max_loaded_latency          = &get_config_property("dl_max_loaded_latency",          undef);
my $dl_max_idle_latency            = &get_config_property("dl_max_idle_latency",            $dl_max_loaded_latency);
my $ul_bw_idle_threshold           = &get_config_property("ul_bw_idle_threshold",           $ul_bw_minimum);
my $dl_bw_idle_threshold           = &get_config_property("dl_bw_idle_threshold",           $dl_bw_minimum);
my $reflectors_csv_file            = &get_config_property("reflectors_csv_file",            undef);
my $number_of_reflectors           = &get_config_property("number_of_reflectors",           undef);
my $reflector_strikeout_threshold  = &get_config_property("reflector_strikeout_threshold",  3);
my $reflector_strike_ttl           = &get_config_property("reflector_strike_ttl",           "auto");
my $tmp_folder                     = &get_config_property("tmp_folder",                     "/tmp");
my $log_file                       = &get_config_property("log_file",                       undef);
my $use_syslog                     = &get_config_property("use_syslog",                     1);
my $latency_check_summary_interval = &get_config_property("latency_check_summary_interval", "auto");
my $status_summary_interval        = &get_config_property("status_summary_interval",        "auto");
my $log_bw_changes                 = &get_config_property("log_bw_changes",                 1);
my $log_details_on_bw_changes      = &get_config_property("log_details_on_bw_changes",      1);

# Debug configuration properties, all disabled by default
my $debug_icmp                     = &get_config_property("debug_icmp",                     0);
my $debug_icmp_timeout             = &get_config_property("debug_icmp_timeout",             0);
my $debug_icmp_correction          = &get_config_property("debug_icmp_correction",          0);
my $debug_icmp_suspend             = &get_config_property("debug_icmp_suspend",             0);
my $debug_icmp_adaptive            = &get_config_property("debug_icmp_adaptive",            0);
my $debug_strike                   = &get_config_property("debug_strike",                   0);
my $debug_latency_check            = &get_config_property("debug_latency_check",            0);
my $debug_sys_commands             = &get_config_property("debug_sys_commands",             0);
my $debug_bw_changes               = &get_config_property("debug_bw_changes",               0);
my $debug_offsets                  = &get_config_property("debug_offsets",                  0);

# Make sure all bandwidth change info is logged if $debug_bw_changes is enabled
if ($debug_bw_changes) {
	$log_bw_changes = 1;
	$log_details_on_bw_changes = 1;
}

# Make sure ICMP timestamp correction debug information is logged if $debug_icmp is enabled
if ($debug_icmp) {
	$debug_icmp_correction = 1;
}

#######################################################################################
# Variables controlled by command line arguments
#######################################################################################

# If $dryrun == 1 the script runs as normal, but bandwidth changes are not applied
my $dryrun = 0;

# If $reset == 1 we will simply reset everything to defaults and exit
my $reset = 0;

#######################################################################################
# Global variables - don't mess with these
#######################################################################################

# Flag to indicate whether we should suspend ICMP threads when idle
my $icmp_adaptive_idle_suspend = $icmp_adaptive && $icmp_interval_idle == 0 ? 1 : 0;

# Number of bad pings required to trigger a "bad" latency result
my $max_bad_pings = &round($max_recent_results * ($bad_ping_pc / 100)) - 1;

# Maximum number of historical bandwidth usage statistics samples to retain.
# We use these samples to check whether the connection is idle, and to check bandwidth
# usage at the time of each request and response, so we need to make sure we have enough
# samples for both.
#
# We calculate what should be the maximum number of samples required for each type of
# usage, plus a couple more to make sure, then select the largest number. Note that a
# couple of extra samples does not impact performance because we always search backwards
# starting with the most recent sample. Redundant samples at the end of the array have
# no impact beyond a *tiny* increase in memory usage.
my $max_for_adaptive_idle_delay = $icmp_adaptive ? &round_up($icmp_adaptive_idle_delay / $latency_check_interval) + 10 : 0;
my $max_for_icmp_results = &round_up( (((max($icmp_interval_loaded, $icmp_interval_idle, 1) * $max_recent_results) + $icmp_timeout) / $latency_check_interval) ) + 10;
my $max_recent_bandwidth_usages = max($max_for_icmp_results, $max_for_adaptive_idle_delay);

# Create an array to store the recent bandwidth usage statistics, and initialise it
my @recent_bandwidth_usages = ();
&update_bandwidth_usage_stats();

# Hashes to store the number of upload/download strikes for each reflector
my %reflector_strikes_ul;
my %reflector_strikes_dl;

# Connection state and the most recent bandwidth changes for each direction
my $connection_down = 0;
my %last_change;
   $last_change{"upload"} = "";
   $last_change{"download"} = "";
my %last_change_time;
   $last_change_time{"upload"} = 0;
   $last_change_time{"download"} = 0;

# Current bandwidth values. Read from UCI during initialisation,
# then updated every time we change the bandwidth.
my $current_bandwidth_ul;
my $current_bandwidth_dl;	

# Average good latency times. Used to calculate increase steps.
my $average_good_latency_ul;
my $average_good_latency_dl;

# Average bandwidth usage for all recent results.
my $average_bandwidth_usage_ul;
my $average_bandwidth_usage_dl;

# Average bandwidth usage at the time that bad pings were detected.
# Used to calculate decrease steps.
my $average_bad_bandwidth_usage_ul;
my $average_bad_bandwidth_usage_dl;

# Increase/decrease step percentages. These are calculated automatically in response to ping results.
my $increase_step_pc_ul;
my $increase_step_pc_dl;
my $decrease_step_pc_ul;
my $decrease_step_pc_dl;

# Log line separator
my $log_line_separator = "--------------------------------------------------------------------------------";
my $last_log_line_was_separator = 0;

# Variables used to control when status summaries and latency check summaries are logged
my $force_status_summary = 1;
my $next_status_summary_time = gettimeofday();
my $next_latency_check_summary_time = gettimeofday();
my $status_summary_auto_frequency = 30;  # i.e. one status summary for every 20 latency summaries

# Number of reflectors that have been struckout
my $struckout_count = 0;

# Flag to indicate whether the reflector pool has ever been exhausted and reloaded
my $reflectors_reloaded_ever = 0;

# Flag to indicate whether the ICMP/reflector warmup has completed
my $icmp_warmup_done = 0;

#######################################################################################
# Initialisation
#######################################################################################

STDOUT->autoflush(1);
STDERR->autoflush(1);

# Process command line arguments
&process_args();

# Record start time
my $script_start_time = gettimeofday();
&output(1, "SQM Autorate started", 1);

# Initialize adaptive ICMP start/total times
my $icmp_adaptive_idle_start_time = $script_start_time;
my $icmp_adaptive_loaded_start_time = $script_start_time;
my $icmp_adaptive_idle_total_time = 0;
my $icmp_adaptive_loaded_total_time = 0;

# Display configuration properties
&output(0, "INIT: Read " . scalar(keys(%config_properties)) . " configuration properties from $config_file: ");
foreach my $key (sort {$a cmp $b} keys(%config_properties)) {
	&output(0, "INIT:\t$key = " . $config_properties{$key});
}

# Get the reflector pool
my @reflector_pool = &get_reflector_pool($reflectors_csv_file);
my $initial_reflector_pool_size = scalar(@reflector_pool);
&output(0, "INIT: Reflector pool size: " . scalar(@reflector_pool));
{
	lock(%reflector_ips);
	%reflector_ips = &get_reflectors($number_of_reflectors);
	
	&output(0, "INIT: Initial reflector list ($number_of_reflectors):");
	foreach my $reflector_ip (keys(%reflector_ips)) {
		&output(0, "INIT:\t$reflector_ip");
	}
}

# Check the configuration
&check_config();

# Set the ICMP interval - default to / start with the "loaded" interval
# This will be modified when idle if adaptive ICMP is enabled
$icmp_interval = $icmp_interval_loaded;
&output(0, "INIT: ICMP interval set to $icmp_interval_idle" . "s");

# If necessary, set the latency check summary interval
if ($latency_check_summary_interval eq "auto") {
	$latency_check_summary_interval = $max_recent_results * $icmp_interval;
}

# If necessary, set the status summary interval
if ($status_summary_interval eq "auto") {
	$status_summary_interval = $latency_check_summary_interval * 30;
}

# If necessary, set the initial strike TTL. 
if ($reflector_strike_ttl eq "auto") {
	&update_reflector_strike_ttl();
	&output(0, "INIT: Reflector strike TTL set to " . $reflector_strike_ttl . "s");
}

# Initialize ICMP packet/byte counters
$icmp_request_count  = 0;
$icmp_request_bytes  = 0;
$icmp_response_count = 0;
$icmp_response_bytes = 0;

# Create a socket on which to send the ping requests
my $fd = &create_icmp_socket();
&output(0, "INIT: Created ICMP socket on FD " . $fd->fileno());

# Create the ICMP receiver thread
my $receiver_thread = &create_receiver_thread($fd);
&output(0, "INIT: Created ICMP Receiver thread: " . $receiver_thread->tid);

# Create the ICMP Sender thread
my $sender_thread = &create_sender_thread($fd);
&output(0, "INIT: Created ICMP Sender thread: " . $sender_thread->tid);

# Get the current bandwidth values from tc
$current_bandwidth_ul = &get_current_bandwidth_from_tc("upload");
$current_bandwidth_dl = &get_current_bandwidth_from_tc("download");

# Check whether the current bandwidths are within the min/max range, and if
# not, fix them. This can happen if the min/max settings are modified
# manually outside of this script.
&ensure_within_min_max();

#######################################################################################
# Main latency checking loop
#######################################################################################

while (1) {
	# Pause for $latency_check_interval. We do this first to give the ICMP
	# Sender/Receiver threads a chance to start up before the first latency check.
	select(undef, undef, undef, $latency_check_interval);
	
	# Update latency check cycle ID
	{
		lock($cid);
		$cid = sprintf("%010d", ++$cid);
	}

	# Print summary of current bandwidth settings if necessary
	if (gettimeofday() >= $next_status_summary_time || $force_status_summary) {
		&print_status_summary();
		
		# Set the time that the next status summary is due
		$next_status_summary_time = gettimeofday() + $status_summary_interval;
		$force_status_summary = 0;
	}

	# If reset is specified, reset bandwidths to standard then finish
	if ($reset) {
		&reset_bandwidth();
		&finish();
	}

	# Now check the latency and get the results
	my ($latency_result, $summary_results_array_ref, $detailed_results_array_ref) = &check_latency();
	
	# Check for and handle changes in connection state
	my $connection_state_changed = 0;
	if ($latency_result == LATENCY_DOWN) {
		$connection_state_changed = &handle_connection_down($summary_results_array_ref, $detailed_results_array_ref);
	} else {
		$connection_state_changed = &handle_connection_up($summary_results_array_ref, $detailed_results_array_ref);
	}

	# Only consider a bandwidth change if we have some valid results
	# and the connection state hasn't just changed
	my $bandwidth_changed = 0;
	if (!$connection_state_changed && $latency_result != LATENCY_INVALID) {
		foreach my $direction ("upload", "download") {
			if (&is_latency_ok($latency_result, $direction)) {
				# Consider whether we should increase, and if not, consider a relax step
				$bandwidth_changed = &increase_if_appropriate($direction, $summary_results_array_ref, $detailed_results_array_ref)
									|| &relax_if_appropriate($direction, $summary_results_array_ref, $detailed_results_array_ref)
									|| $bandwidth_changed;
			} else {
				$bandwidth_changed = &decrease_if_appropriate($direction, $summary_results_array_ref, $detailed_results_array_ref)
									|| $bandwidth_changed;
			}
		}
	}

	if ($bandwidth_changed) {
		# Print a status summary on the next cycle
		$force_status_summary = 1;
	} else {
		# Print appropriate output if the bandwidth hasn't changed

		if ($debug_latency_check) { &print_latency_results_details(@{$detailed_results_array_ref}); }
			
		# Print latency check results summary if necessary
		if ($latency_check_summary_interval > 0 && gettimeofday() >= $next_latency_check_summary_time) {
			&print_latency_results_summary(@{$summary_results_array_ref});
			$next_latency_check_summary_time = gettimeofday() + $latency_check_summary_interval;
		}
	}
	
	if ($debug_latency_check) { &output(0, "LATENCY CHECK DEBUG: overall result = $latency_result"); }

} # End of main loop

#######################################################################################
# Threads
#######################################################################################

# Thread to send ICMP timestamp requests
sub create_sender_thread {
	my ($fd) = @_;

	return threads->create(sub {
		my $thr_id = threads->self->tid;
		
		my @reflector_ips;

		while (1) {			
			{
				lock(%reflector_ips);
				@reflector_ips = keys(%reflector_ips);				
			}

			foreach my $reflector_ip (@reflector_ips) {
				&suspend_self_if_required("sender");
				
				# Go through the requests hash and record/clear any requests that have timed out
				# We need to do this here (i.e. instead of on the receiver thread) to ensure that
				# requests time out promptly when the connection is in a really bad way or
				# completely down. Under normal circumstances this operation is very cheap because
				# there will be a very small number of pending requests (usually zero in fact).
				&process_icmp_timeouts();
				
				# Get the current time
				my $current_time = gettimeofday();					
								
				# Send an ICMP timestamp request
				my ($id, $seq) = &send_icmp_timestamp_request($reflector_ip, $fd);

				my $request_sig = "$reflector_ip $id $seq";
					
				# Store the time at which we sent this request
				# We'll use this to calculate bandwidth usage when we process the result
				{
					lock(%icmp_sent_times);
					$icmp_sent_times{$request_sig} = $current_time;
				}

				{
					# Calculate and store the time at which this request will timeout
					lock(%icmp_timeout_times);
					$icmp_timeout_times{$request_sig} = $current_time + $icmp_timeout;
				}
				
				select(undef, undef, undef, $icmp_interval);
			}
		}
	});
}

# Thread to receive ICMP timestamp replies
sub create_receiver_thread {
	my ($fd) = @_;

	return threads->create(sub {
		my $thr_id = threads->self->tid;

		my $rin = "";
		vec($rin, $fd->fileno(), 1) = 1;
		while (1) {
			&suspend_self_if_required("receiver");
			
			# Block and wait for a packet to arrive
			# TODO: This never actually seems to block? It always returns
			#       instantly and we block in recv() instead...
			my $nfound = select((my $rout = $rin), undef, undef, 0);	
			
			if ($nfound != -1) {
				# Receive the packet and get the packed address.
				my $recv_msg;
				my $packed_addr = recv($fd, $recv_msg, 1500, 0);
				
				if (defined($packed_addr)) {				
					# Unpack the socket address info (port will always be zero)
					my ($from_port, $from_ip) = unpack_sockaddr_in($packed_addr);
								
					# Get the ICMP type from the packet
					my $reply_type = unpack("C", substr($recv_msg, ICMP_PAYLOAD_OFFSET, 1));

					# If this is a timestamp reply, handle it
					if ($reply_type == ICMP_TIMESTAMP_REPLY) {
						&handle_icmp_reply(inet_ntoa($from_ip), $recv_msg);
					}
				}
			}
		}
	});
}

# Suspend ICMP sender and receiver threads
# The threads will remain suspended until &resume_icmp_threads() is called
sub suspend_icmp_threads {
	# Check we are running on the main thread
	my $thread_id = threads->self->tid;
	if ($thread_id != 0) {
		&fatal_error("suspend_icmp_threads() called from thread $thread_id");
	}

	# We will suspend the ICMP Receiver thread first. If we suspend the Sender first
	# the Receiver will hang briefly in recv() waiting for an ICMP response.

	if (defined($receiver_thread) && $receiver_thread->is_running()) {
		# Set flag to signal that the ICMP Receiver thread needs to suspend itself
		{ 
			lock($suspend_icmp_receiver);
			$suspend_icmp_receiver = 1;
			if ($debug_icmp_suspend) { &output(0, "ICMP SUSPEND DEBUG: ICMP Receiver suspend requested"); }
		}
	
		# Wait for the ICMP Receiver thread to suspend itself	
		{
			lock($receiver_suspended);
			while (!$receiver_suspended) {
				cond_wait($receiver_suspended);
			}
			if ($debug_icmp_suspend) { &output(0, "ICMP SUSPEND DEBUG: ICMP Receiver suspend confirmed"); }
		}
	} else {
		if ($debug_icmp_suspend) { &output(0, "ICMP SUSPEND DEBUG: ICMP Receiver not running"); }
	}
	
	if (defined($sender_thread) && $sender_thread->is_running()) {
		# Set flag to signal that the ICMP Sender thread needs to suspend itself
		{ 
			lock($suspend_icmp_sender);
			$suspend_icmp_sender = 1;
			if ($debug_icmp_suspend) { &output(0, "ICMP SUSPEND DEBUG: ICMP Sender suspend requested"); }
		}
	
		# Wait for the ICMP Sender thread to suspend itself
		{
			lock($sender_suspended);
			while (!$sender_suspended) {
				cond_wait($sender_suspended);
			}
			if ($debug_icmp_suspend) { &output(0, "ICMP SUSPEND DEBUG: ICMP Sender suspend confirmed"); }
		}
	} else {
		if ($debug_icmp_suspend) { &output(0, "ICMP SUSPEND DEBUG: ICMP Sender not running"); }
	}
}

# Resume suspended ICMP sender and receiver threads
sub resume_icmp_threads {
	# Check we are running on the main thread
	my $thread_id = threads->self->tid;
	if ($thread_id != 0) {
		&fatal_error("resume_icmp_threads() called from thread $thread_id");
	}
	
	# We will resume the ICMP Receiver thread first. If we resumed the Sender first
	# the Receiver might miss some ICMP responses.

	if (defined($receiver_thread) && $receiver_thread->is_running()) {
		# Set flag to signal that the ICMP Receiver thread can resume itself
		{ 
			lock($suspend_icmp_receiver);
			$suspend_icmp_receiver = 0;
			cond_broadcast($suspend_icmp_receiver);
		
			if ($debug_icmp_suspend) { &output(0, "ICMP SUSPEND DEBUG: ICMP Receiver resume requested"); }
		}
	
		# Wait for the ICMP Receiver thread to resume
		{		
			lock($receiver_suspended);
			while ($receiver_suspended) {
				if ($debug_icmp_suspend) { &output(0, "ICMP SUSPEND DEBUG: Waiting for ICMP Receiver to resume"); }
				cond_wait($receiver_suspended);
			}
		}
		if ($debug_icmp_suspend) { &output(0, "ICMP SUSPEND DEBUG: ICMP Receiver resume confirmed"); }
	} else {
		if ($debug_icmp_suspend) { &output(0, "ICMP SUSPEND DEBUG: ICMP Receiver not running"); }
	}
	
	if (defined($sender_thread) && $sender_thread->is_running()) {
		# Set flag to signal that the ICMP Sender thread can resume itself
		{ 
			lock($suspend_icmp_sender);
			$suspend_icmp_sender = 0;
			cond_broadcast($suspend_icmp_sender);
			if ($debug_icmp_suspend) { &output(0, "ICMP SUSPEND DEBUG: ICMP Sender resume requested"); }
		}
	
		# Wait for the ICMP Sender thread to resume
		{
			lock($sender_suspended);
			while ($sender_suspended) {
				if ($debug_icmp_suspend) { &output(0, "ICMP SUSPEND DEBUG: Waiting for ICMP Sender to resume"); }
				cond_wait($sender_suspended);
			}
			if ($debug_icmp_suspend) { &output(0, "ICMP SUSPEND DEBUG: ICMP Sender resume confirmed"); }
		}
	} else {
		if ($debug_icmp_suspend) { &output(0, "ICMP SUSPEND DEBUG: ICMP Sender not running"); }
	}
}

# Called by the ICMP Sender and Receiver threads to suspend themselves
sub suspend_self_if_required {
	my ($thread_type) = @_;

	# Check we are not running on the main thread
	my $thread_id = threads->self->tid;
	if ($thread_id == 0) {
		&fatal_error("ERROR: suspend_self_if_required() called from main thread");
	}

	# Code for ICMP Sender thread
	if ($thread_type eq "sender") {
		lock($suspend_icmp_sender);
		if ($suspend_icmp_sender) {			
			# Broadcast the fact that we are suspended
			{
				lock($sender_suspended);
				$sender_suspended = 1;
				if ($debug_icmp_suspend) { &output(0, "ICMP SUSPEND DEBUG: ICMP Sender suspended"); }
				cond_broadcast($sender_suspended);
			}
		
			# Wait until safepoint no longer required
			while($suspend_icmp_sender) {
				if ($debug_icmp_suspend) { &output(0, "ICMP SUSPEND DEBUG: ICMP Sender waiting to resume"); }
				cond_wait($suspend_icmp_sender);				
			}

			if ($debug_icmp_suspend) { &output(0, "ICMP SUSPEND DEBUG: Resuming ICMP Sender"); }

			{
				lock($sender_suspended);
				$sender_suspended = 0;
				if ($debug_icmp_suspend) { &output(0, "ICMP SUSPEND DEBUG: ICMP Sender resumed"); }
				cond_broadcast($sender_suspended);
			}
		}
	}

	# Code for ICMP Receiver thread
	if ($thread_type eq "receiver") {
		lock($suspend_icmp_receiver);
		if ($suspend_icmp_receiver) {
			# Broadcast the fact that we are suspended
			{
				lock($receiver_suspended);
				$receiver_suspended = 1;
				if ($debug_icmp_suspend) { &output(0, "ICMP SUSPEND DEBUG: ICMP Receiver suspended"); }
				cond_broadcast($receiver_suspended);
			}

			# Wait until safepoint no longer required
			while($suspend_icmp_receiver) {
				if ($debug_icmp_suspend) { &output(0, "ICMP SUSPEND DEBUG: ICMP Receiver waiting to resume"); }
				cond_wait($suspend_icmp_receiver);				
			}

			if ($debug_icmp_suspend) { &output(0, "ICMP SUSPEND DEBUG: Resuming ICMP Receiver"); }

			{
				lock($receiver_suspended);
				$receiver_suspended = 0;
				if ($debug_icmp_suspend) { &output(0, "ICMP SUSPEND DEBUG: ICMP Receiver resumed"); }
				cond_broadcast($receiver_suspended);
			}
		}
	}
}

sub are_icmp_threads_suspended {
	# Check we are running on the main thread
	my $thread_id = threads->self->tid;
	if ($thread_id != 0) {
		&fatal_error("ERROR: are_icmp_threads_suspended() called from thread $thread_id");
	}

	lock($suspend_icmp_sender);
	lock($suspend_icmp_receiver);
	lock($sender_suspended);
	lock($receiver_suspended);

	if ($suspend_icmp_sender && $suspend_icmp_receiver && $sender_suspended && $receiver_suspended) {
		return 1;
	} else {
		return 0;
	}
}

#######################################################################################
# Error handlers
#######################################################################################

sub signal_handler {
	&output(0, "Caught signal: $!");
	&output(0, "Suspending ICMP threads\n");
	suspend_icmp_threads();
	&finish();
}

# Handle a fatal error.
# This should only be called from the main thread.
sub fatal_error {
	my ($msg) = @_;
	&finish("FATAL ERROR: $msg");	
}

# Print a message to the log and the syslog indicating that the script
# stopped, then exit. This should only be called from the main thread, but
# we'll do our best if it was somehow called from one of the ICMP threads.
# An optional additional log message can also be passed as an argument.
sub finish {
	my ($msg) = @_;
	
	# Send finish message(s) to the syslog by default
	my $send_to_syslog = 1;
	
	# Check we are running on the main thread
	# If this isn't the main thread, don't send the log messages
	# to the syslog. This is to avoid a deadlock when we fork the
	# logger command, because we can't suspend the other threads.
	my $thread_id = threads->self->tid;
	if ($thread_id != 0) {
		&output(0, "WARNING: finish() called from thread $thread_id");
		$send_to_syslog = 0;
	}
	
	# Print additional message if one was given to us
	if (defined($msg) && $msg ne "") {
		&output($send_to_syslog, $msg, 1);
	}
	
	&output($send_to_syslog, "SQM Autorate stopped", 1);

	if (defined($sender_thread))   { $sender_thread->detach();   }
	if (defined($receiver_thread)) { $receiver_thread->detach(); }

	exit();
}



#######################################################################################
# Subroutines
#######################################################################################

# Process command line arguments
sub process_args {
	foreach my $arg (@ARGV) {
		if ($arg eq "dryrun") {
			$dryrun = 1;
		}

		if ($arg eq "reset") {
			$reset = 1;
		}
	}
}

# Get the configuration properties from the specified file
# Returns a hash of the property keys and values
sub get_config_properties {
	my ($config_file) = @_;

	my %properties;

	open(PROPERTIES_FILE, '<', $config_file) || &fatal_error("Failed to open configuration file \"$config_file\"");
	foreach my $line (<PROPERTIES_FILE>) {
		# Remove all whitespace
		$line =~ s/\s+//g;

		# Remove comments
		$line =~ s/#.*//g;

		if ($line =~ /^(.+)=(.+)$/) {
			my $key = $1;
			my $value = $2;

			if ($value =~ /^\$(.+)$/) {
				# This value points to another key
				my $other_key = $1;
				$properties{$key} = $properties{$other_key};
			} else {
				$properties{$1} = $2;
			}
		}
	}
	close(PROPERTIES_FILE);

	return %properties;
}

# Returns the value of a configuration property, or the specified default value.
# Note: the global %config_properties hash must be populated before this is called.
sub get_config_property {
	my ($property_key, $default_value) = @_;
	
	if (exists($config_properties{$property_key})) {
		return $config_properties{$property_key};
	} else {
		return $default_value;
	}
}

# Check configuration
sub check_config {
	my $fatal_error = 0;

	if ($dryrun) {
		&output(0, "INIT: WARNING: Dry run - configuration changes will not be applied");
	}
	
	if (&check_interfaces() == -1) {
		$fatal_error = 1;
	}
		
	if (!defined($wan_interface) || $wan_interface eq "") {
		&output(0, "INIT: ERROR: WAN interface (\"wan_interface\") not set");
		$fatal_error = 1;
	} elsif (scalar(&get_wan_bytes()) == 0) {
		&output(0, "INIT: ERROR: Failed to get statistics for WAN interface \"$wan_interface\" from /proc/net/dev");
		$fatal_error = 1;
	}
	
	if (!defined($dl_bw_minimum)) {
		&output(0, "INIT: ERROR: Minimum download bandwidth (\"dl_bw_minimum\") not set");
		$fatal_error = 1;
	}
	
	if (!defined($dl_bw_standard)) {
		&output(0, "INIT: ERROR: Standard download bandwidth (\"dl_bw_standard\") not set");
		$fatal_error = 1;
	}
	
	if (!defined($dl_bw_maximum)) {
		&output(0, "INIT: ERROR: Maximum download bandwidth (\"dl_bw_maximum\") not set");
		$fatal_error = 1;
	}
	
	if (!defined($ul_bw_minimum)) {
		&output(0, "INIT: ERROR: Minimum upload bandwidth (\"ul_bw_minimum\")not set");
		$fatal_error = 1;
	}
	
	if (!defined($ul_bw_standard)) {
		&output(0, "INIT: ERROR: Standard upload bandwidth (\"ul_bw_standard\") not set");
		$fatal_error = 1;
	}
	
	if (!defined($ul_bw_maximum)) {
		&output(0, "INIT: ERROR: Maximum upload bandwidth (\"ul_bw_maximum\") not set");
		$fatal_error = 1;
	}
	
	if (
		defined($dl_bw_minimum) && defined($dl_bw_standard) && defined($dl_bw_maximum) &&
		defined($ul_bw_minimum) && defined($ul_bw_standard) && defined($ul_bw_maximum)
	) {
		if ($dl_bw_minimum >= $dl_bw_maximum) {
			&output(0, "INIT: ERROR: Minimum download bandwidth (\"dl_bw_minimum\") must be lower than maximum download bandwidth (\"dl_bw_maximum\")");
			$fatal_error = 1;
		}
	
		if ($ul_bw_minimum >= $ul_bw_maximum) {
			&output(0, "INIT: ERROR: Minimum upload bandwidth (\"ul_bw_minimum\") must be lower than maximum upload bandwidth (\"ul_bw_maximum\")");
			$fatal_error = 1;
		}
	
		if ($dl_bw_standard <= $dl_bw_minimum || $dl_bw_standard >= $dl_bw_maximum) {
			&output(0, "INIT: ERROR: Standard download bandwidth (\"dl_bw_standard\") must be between minimum and maximum download bandwidths (\"dl_bw_minimum\" and \"dl_bw_maximum\")");
			$fatal_error = 1;
		}
	
		if ($ul_bw_standard <= $ul_bw_minimum || $ul_bw_standard >= $ul_bw_maximum) {
			&output(0, "INIT: ERROR: Standard upload bandwidth (\"ul_bw_standard\") must be between minimum and maximum upload bandwidths (\"ul_bw_minimum\" and \"ul_bw_maximum\")");
			$fatal_error = 1;
		}
	}
	
	if ($max_recent_results < 1) {
		&output(0, "INIT: ERROR: Maximum recent results (\"max_recent_results\") must be greater than 0");
		$fatal_error = 1;
	}
	
	if ($increase_load_threshold_pc < 0 || $increase_load_threshold_pc > 100) {
		&output(0, "INIT: ERROR: Increase load threshold percentage (\"increase_load_threshold_pc\") must be between 0 and 100");
		$fatal_error = 1;
	}
	
	if ($increase_delay_after_decrease < 0) {
		&output(0, "INIT: ERROR: Increase delay after increase (\"increase_delay_after_decrease\") cannot be negative");
		$fatal_error = 1;
	}
	
	if ($increase_delay_after_decrease < 0) {
		&output(0, "INIT: ERROR: Increase delay after decrease (\"increase_delay_after_decrease\") cannot be negative");
		$fatal_error = 1;
	}
	
	if ($relax_delay < 0) {
		&output(0, "INIT: ERROR: Relaxation delay (\"relax_delay\") cannot be negative");
		$fatal_error = 1;
	}
	
	if ($relax_pc < 0) {
		&output(0, "INIT: ERROR: Relaxation percentage step (\"relax_pc\") cannot be negative");
		$fatal_error = 1;
	}
	
	if ($relax_load_threshold_pc < 0 || $relax_load_threshold_pc > 100) {
		&output(0, "INIT: ERROR: Relaxation load threshold percentage (\"relax_load_threshold_pc\") must be between 0 and 100");
		$fatal_error = 1;
	}

	if ($icmp_adaptive_idle_delay <= $latency_check_interval) {
		&output(0, "INIT: ERROR: Adaptive ICMP idle delay (\"icmp_adaptive_idle_delay\") must be greater than latency_check_interval ($latency_check_interval)");
		$fatal_error = 1;
	}

	if ($icmp_interval_idle < 0) {
		&output(0, "INIT: ERROR: ICMP interval (\"icmp_interval_idle\") cannot be less than 0");
		$fatal_error = 1;
	}
	
	if ($icmp_interval_loaded <= 0) {
		&output(0, "INIT: ERROR: ICMP interval (\"icmp_interval_loaded\") must be greater than 0");
		$fatal_error = 1;
	}
	
	if ($icmp_timeout <= 0) {
		&output(0, "INIT: ERROR: ICMP timeout (\"icmp_timeout\") must be greater than 0");
		$fatal_error = 1;
	}
	
	if ($latency_check_interval < 0) {
		&output(0, "INIT: ERROR: Latency check interval (\"latency_check_interval\") cannot be negative");
		$fatal_error = 1;
	}

	if ($latency_check_summary_interval ne "auto" && $latency_check_summary_interval < 0) {
		&output(0, "INIT: ERROR: Latency check summary interval (\"latency_check_summary_interval\") cannot be negative");
		$fatal_error = 1;
	}
	
	if ($status_summary_interval ne "auto" && $status_summary_interval < 0) {
		&output(0, "INIT: ERROR: Status summary interval (\"status_summary_interval\") cannot be negative");
		$fatal_error = 1;
	}
	
	if ($bad_ping_pc < 0 || $bad_ping_pc > 100) {
		&output(0, "INIT: ERROR: Bad ping percentage (\"bad_ping_pc\") must be between 0 and 100");
		$fatal_error = 1;
	}

	if ($ul_max_idle_latency < 0) {
		&output(0, "INIT: ERROR: Maximum idle upload latency (\"ul_max_idle_latency\") cannot be negative");
		$fatal_error = 1;
	}
	
	if ($dl_max_idle_latency < 0) {
		&output(0, "INIT: ERROR: Maximum idle download latency (\"dl_max_idle_latency\") cannot be negative");
		$fatal_error = 1;
	}

	if (!defined($ul_max_loaded_latency) || $ul_max_loaded_latency < 0) {
		&output(0, "INIT: ERROR: Maximum loaded upload latency (\"ul_max_loaded_latency\") must be set to positive value");
		$fatal_error = 1;
	}

	if (!defined($dl_max_loaded_latency) || $dl_max_loaded_latency < 0) {
		&output(0, "INIT: ERROR: Maximum loaded download latency (\"dl_max_loaded_latency\") must be set to positive value");
		$fatal_error = 1;
	}

	if ($ul_bw_idle_threshold < 0 || $ul_bw_idle_threshold >= $ul_bw_maximum) {
		&output(0, "INIT: ERROR: Upload idle bandwidth threshold (\"ul_bw_idle_threshold\") must be between 0 and maximum upload bandwidth (\"ul_bw_maximum\")");
		$fatal_error = 1;
	}
	
	if ($dl_bw_idle_threshold < 0 || $dl_bw_idle_threshold >= $dl_bw_maximum) {
		&output(0, "INIT: ERROR: Download idle bandwidth threshold (\"dl_bw_idle_threshold\") must be between 0 and maximum download bandwidth (\"dl_bw_maximum\")");
		$fatal_error = 1;
	}
	
	if (!defined($reflectors_csv_file) || $reflectors_csv_file eq "") {
		&output(0, "INIT: ERROR: No reflector CSV file specified (\"reflectors_csv_file\"). Download one for your region from https://github.com/tievolu/timestamp-reflectors");
		$fatal_error = 1;
	} elsif (! -e $reflectors_csv_file) {
		&output(0, "INIT: ERROR: Specified reflector CSV file does not exist: $reflectors_csv_file");
		$fatal_error = 1;
	}
	
	if ($number_of_reflectors <= 0) {
		&output(0, "INIT: ERROR: Number of reflectors (\"number_of_reflectors\") must be greater than 0");
		$fatal_error = 1;
	}

	if ($reflector_strikeout_threshold < 0) {
		&output(0, "INIT: ERROR: Reflector strikeout threshold (\"reflector_strikeout_threshold\") cannot be less than 0");
		$fatal_error = 1;
	}
	
	if (defined($log_file) && $log_file ne "") {
		if ($log_file =~ /(.+)\/.+/) {
			my $log_directory = $1;
			if (! -e $log_directory) {
				&output(0, "ERROR: Directory specified for log file (\"log_file\") does not exist: $log_directory");
				$fatal_error = 1;
			}			
		}
	}

	if ($fatal_error) {
		&fatal_error("Invalid configuration. See log for more details.");
	}
}

# Check that SQM instances exist for the configured interfaces
sub check_interfaces {
	my @qdiscs = split(/\n/, &run_sys_command("tc -d qdisc"));
	
	# Return value of 1 means success. -1 will be returned if we hit a problem.
	my $return_value = 1;
	
	# Upload interfaces
	UL_INTERFACE: for (my $i = 0; $i < scalar(@ul_interfaces); $i++) {
		foreach my $qdisc (@qdiscs) {
			# Check specified interface as-is
			if ($qdisc =~ / dev $ul_interfaces[$i] /) {
				&output(0, "INIT: Found upload SQM instance on " . $ul_interfaces[$i]);
				next UL_INTERFACE;
			}
		}
		
		&output(0, "INIT: ERROR: No upload SQM instance found for $ul_interfaces[$i] - check configuration");
		$return_value = -1;
	}
	
	# Download interfaces
	DL_INTERFACE: for (my $i = 0; $i < scalar(@dl_interfaces); $i++) {
		foreach my $qdisc (@qdiscs) {
			# Check interface as-is if this interface is not already configured as an upload interface
			if (!grep(/$dl_interfaces[$i]/, @ul_interfaces) && $qdisc =~ / dev $dl_interfaces[$i] /) {
				&output(0, "INIT: Found download SQM instance on " . $dl_interfaces[$i]);
				next DL_INTERFACE;
			}
			
			# If this is a non-IFB interface, check for a corresponding IFB interface
			if ($dl_interfaces[$i] !~ /^ifb4/ && $qdisc =~ / dev ifb4$dl_interfaces[$i] /) {
				# Found IFB interface - modify configuration accordingly
				$dl_interfaces[$i] = "ifb4" . $dl_interfaces[$i];
				&output(0, "INIT: Found download SQM instance on " . $dl_interfaces[$i]);
				next DL_INTERFACE;
			}
		}
		
		&output(0, "INIT: ERROR: No download SQM instance found for $dl_interfaces[$i] - check configuration");
		$return_value = -1;
	}
	
	return $return_value;
}

# Print the specified message to the console and log file, if enabled.
# If $send_to_syslog == 1 the message is also sent to the syslog, unless $use_syslog == 0.
# If $dryrun == 1 messages are only printed to the console.
# If $high_priority == 1, syslog priority user.alert is used, otherwise we use the default (user.notice)
sub output {
	my ($send_to_syslog, $message, $high_priority) = @_;

	# PID and cycle ID
	my $id;
	{
		lock($pid);
		lock($cid);
		$id = "$pid-$cid";
	}

	# Add a timestamp / cycle ID prefix to each line of the message
	# for printing to the console and log file
	my $prefix = &localtime_millis() . " [$id]:";
	my $prefixed_message = "";
	if ($message =~ /\n/) {
		foreach my $message_line (split(/\n/, $message)) {
			$prefixed_message .= "$prefix $message_line\n";
		}
		chomp($prefixed_message);
	} else {
		$prefixed_message = "$prefix $message";
	}
	
	{
		lock($output_lock);
		
		# Print to the console
		print("$prefixed_message\n");
		
		if (!$dryrun) {
			if (defined($log_file) && $log_file ne "") {
				# Print to the log file
				open(LOGFILE, '>>', $log_file) || die("Could not open log file: $log_file\n");
				LOGFILE->autoflush(1);
				print(LOGFILE "$prefixed_message\n");
				close(LOGFILE);
			}
		}
		
		# Set the flag to show that we just printed something that isn't a log line separator
		$last_log_line_was_separator = 0;
	}

	if (!$dryrun) {
		# Send to the syslog
		# This must only be done on the main thread, and not while holding $output_lock
		if ($send_to_syslog && $use_syslog) {
			my $logger_command;
			if ($high_priority) {
				$logger_command = "logger -p user.alert -t SQM-Autorate[$id]";
			} else {
				$logger_command = "logger -t SQM-Autorate[$id]";
			}
			&run_sys_command("$logger_command \"$message\"");
		}
	}
}

# Print/log a latency check results summary
sub print_latency_results_summary {
	my ($total_results,
		$ul_bad_count,
		$dl_bad_count,
		$timed_out_count,
		$ul_bw_ave,
		$dl_bw_ave,
		$valid_pings_ul_ref,
		$valid_pings_dl_ref
	) = @_;
	
	if (!defined($total_results) || $total_results == 0) {
		&output(0, sprintf(
			"LATENCY SUMMARY: count=0 ul_bad=0 dl_bad=0 timed_out=0 ul_ave=0 ul_max=0 ul_jit=0 dl_ave=0 dl_max=0 dl_jit=0 ul_bw_ave=%-7s dl_bw_ave=%-7s",
			sprintf("%0.3f", &kbps_to_mbps($ul_bw_ave)),                    # ul_bw_ave
			sprintf("%0.3f", &kbps_to_mbps($dl_bw_ave))                     # dl_bw_ave
		));
		return;
	}
	
	if (!defined($valid_pings_ul_ref) || !defined($valid_pings_dl_ref)) {
		&output(0, "LATENCY SUMMARY: No valid results!");
		return;
	}
	
	my @valid_pings_ul = @{$valid_pings_ul_ref};
	my @valid_pings_dl = @{$valid_pings_dl_ref};
	
	my $ul_time_ave = 0;
	if (scalar(@valid_pings_ul) != 0) {
		$ul_time_ave = sum(@valid_pings_ul)/scalar(@valid_pings_ul);
	}
	
	my $dl_time_ave = 0;
	if (scalar(@valid_pings_dl) != 0) {
		$dl_time_ave = sum(@valid_pings_dl)/scalar(@valid_pings_dl);
	}
	
	&output(0, sprintf(
		"LATENCY SUMMARY: count=%-3s ul_bad=%-3s dl_bad=%-3s timed_out=%-3d ul_ave=%-6s ul_max=%-3s ul_jit=%-6s dl_ave=%-6s dl_max=%-3s dl_jit=%-6s ul_bw_ave=%-7s dl_bw_ave=%-7s",
		$total_results,
		$ul_bad_count,
		$dl_bad_count,
		$timed_out_count,
		sprintf("%0.2f", $ul_time_ave),                                 # ul_time_ave
		scalar(@valid_pings_ul) != 0 ? max(@valid_pings_ul) : 0,        # ul_time_max
		sprintf("%0.2f", &get_jitter(@valid_pings_ul)),                 # ul_jitter
		sprintf("%0.2f", $dl_time_ave),                                 # dl_time_ave
		scalar(@valid_pings_dl) != 0 ? max(@valid_pings_dl) : 0,        # dl_time_max
		sprintf("%0.2f", &get_jitter(@valid_pings_dl)),                 # dl_jitter
		sprintf("%0.3f", &kbps_to_mbps($ul_bw_ave)),                    # ul_bw_ave
		sprintf("%0.3f", &kbps_to_mbps($dl_bw_ave))                     # dl_bw_ave
	));
}

# Print/log the detailed results for a latency check, describing each individual ICMP result
sub print_latency_results_details {
	my @detailed_results_array = @_;
	
	my $detailed_results;
	
	if (scalar(@detailed_results_array) == 0) {
		# No results. Nothing to do.
		return;
	}
	
	foreach my $result_array_ref (@detailed_results_array) {
		my (
			$sent_time,
			$ip,
			$packet_id,
			$seq,
			$ul_time,
			$dl_time,
			$ul_bw,
			$dl_bw,
			$ul_good,
			$dl_good,
			$ul_strike,
			$dl_strike,
			$ignored
		) = @{$result_array_ref};
		
		$detailed_results .= sprintf(
			"LATENCY DETAIL: sent=%s ip=%-15s id=%-5s seq=%-5s ul_time=%-5s dl_time=%-5s ul_bw=%-7s dl_bw=%-7s ul=%-4s dl=%-4s ul_strike=%-3s dl_strike=%-3s %s\n",
			&format_time($sent_time),
			$ip,
			$packet_id,
			$seq,
			$ul_time,
			$dl_time,
			&kbps_to_mbps($ul_bw),
			&kbps_to_mbps($dl_bw),
			$ul_good ? "good" : "bad",
			$dl_good ? "good" : "bad",
			$ul_strike == -1 ? "n/a" : ($ul_strike ? "yes" : "no"),
			$dl_strike == -1 ? "n/a" : ($dl_strike ? "yes" : "no"),
			$ignored ? "IGNORED" : ""
		);		
	}

	&output(0, $detailed_results);
}

# Print/log a status summary showing current bandwidth settings,
# thresholds, and whether increases/descreases are disallowed in
# either direction
sub print_status_summary {
	my $status_summary = "";
	
	&print_log_line_separator_if_necessary();
	&output(0, "Current SQM bandwidth: " . &get_current_bandwidth("download") . " Kb/s download, " . &get_current_bandwidth("upload") . " Kb/s upload");

	if (!$connection_down) {
		foreach my $direction ("upload", "download") {
			&is_bandwidth_at_min($direction, 1);
			&is_increase_allowed($direction, 1);
			if (&get_current_bandwidth($direction) != &get_std_bandwidth($direction)) {
				&is_relax_allowed($direction, 1);
			}
		}
	} else {
		&output(0, "Internet connection appears to be down.");
	}
	
	my $threshold_summary = "";
	
	$threshold_summary .= sprintf(
		"Decrease thresholds - UL: >%dms / >%.3fMbps, DL: >%dms / >%.3fMbps, Bad pings (per target): >%d/%d\n",
		$ul_max_loaded_latency,
		&kbps_to_mbps($ul_bw_idle_threshold),
		$dl_max_loaded_latency,
		&kbps_to_mbps($dl_bw_idle_threshold),
		$max_bad_pings,
		$max_recent_results
	);
	
	$threshold_summary .= sprintf(
		"Increase thresholds - UL: <%dms / >%.3fMbps, DL: <%dms / >%.3fMbps\n",
		$ul_max_loaded_latency,
		&kbps_to_mbps(&get_current_bandwidth("upload")) * ($increase_load_threshold_pc / 100),
		$dl_max_loaded_latency,
		&kbps_to_mbps(&get_current_bandwidth("download")) * ($increase_load_threshold_pc / 100),
	);

	$threshold_summary .= sprintf(
		"Relaxation thresholds - UL: <%dms / <%.3fMbps, DL: <%dms / <%.3fMbps",
		$ul_max_loaded_latency,
		(&get_current_bandwidth("upload")/1000) * ($relax_load_threshold_pc / 100),
		$dl_max_loaded_latency,
		(&get_current_bandwidth("download")/1000) * ($relax_load_threshold_pc / 100)
	);

	my $icmp_summary = "";
	
	{
		lock($icmp_response_count);
		lock($icmp_response_bytes);
		$icmp_summary .= sprintf(
			"ICMP - requests: %d (%s MB), responses: %d (%s MB), loaded/idle interval = %ss/%s",
			$icmp_request_count,
			sprintf("%.2f", $icmp_request_bytes / 1048576),
			$icmp_response_count,
			sprintf("%.2f", $icmp_response_bytes / 1048576),
			$icmp_interval_loaded,
			$icmp_adaptive_idle_suspend ? "inf" : $icmp_interval_idle . "s"
		);
	}
	
	my $uptime_summary = "";
	
	if ($icmp_adaptive) {
		$uptime_summary .= sprintf(
			"Uptime - total: %s, loaded: %s, idle: %s",
			&script_uptime(),
			&format_duration(&get_icmp_adaptive_total_time("loaded")),
			&format_duration(&get_icmp_adaptive_total_time("idle"))
		);
	} else {
		$uptime_summary .= sprintf(
			"Uptime - %s",
			&script_uptime()
		);
	}		

	# Only print the reflector summary if strikes are enabled
	if ($reflector_strikeout_threshold != 0) {
		my $reflector_summary = sprintf(
			"Reflectors - in use: %d, strikeout threshold: %d, strike TTL loaded/idle: %ds/%ds, struckout: %d, pool: %d/%d",
			$number_of_reflectors,
			$reflector_strikeout_threshold,
			&round(($number_of_reflectors / (1 / $icmp_interval_loaded)) * ($reflector_strikeout_threshold + 1)),
			$icmp_adaptive_idle_suspend ? "inf" : &round(($number_of_reflectors / (1 / $icmp_interval_idle)) * ($reflector_strikeout_threshold + 1)),
			$struckout_count,
			scalar(@reflector_pool),
			$initial_reflector_pool_size
		);		
		&output(0, "$threshold_summary\n$icmp_summary\n$uptime_summary\n$reflector_summary");
	} else {
		&output(0, "$threshold_summary\n$icmp_summary\n$uptime_summary");
	}
	
	&print_log_line_separator_if_necessary();
}

# Update the latency check and status summary intervals if they are configured to
# be updated automatically. Ensure that the next summaries are printed at the
# correct times.
sub update_auto_summary_intervals {
	# Latency check summary
	if (&get_config_property("latency_check_summary_interval", "auto") eq "auto") {
		my $previous_latency_check_summary_time = $next_latency_check_summary_time - $latency_check_summary_interval;
		if ($icmp_adaptive_idle_suspend && &are_icmp_threads_suspended()) {
			# TODO: is there a way to calculate a sensible interval here instead of hard-coding it?
			$latency_check_summary_interval = 20;
		} else {
			$latency_check_summary_interval = $max_recent_results * $icmp_interval;
		}
		$next_latency_check_summary_time = $previous_latency_check_summary_time + $latency_check_summary_interval;
		if ($debug_icmp_adaptive) { &output(0, "ICMP ADAPTIVE DEBUG: Latency check summary interval set to " . $latency_check_summary_interval . "s, next summary at " . &format_time($next_latency_check_summary_time)); }
	}

	# Status summary
	if (&get_config_property("status_summary_interval", "auto") eq "auto") {
		my $previous_status_summary_time = $next_status_summary_time - $status_summary_interval;
		$status_summary_interval = $latency_check_summary_interval * $status_summary_auto_frequency;
		$next_status_summary_time = $previous_status_summary_time + $status_summary_interval;
		if ($debug_icmp_adaptive) { &output(0, "ICMP ADAPTIVE DEBUG: Status summary interval set to " . $status_summary_interval . "s, next summary at " . &format_time($next_status_summary_time)); }
	}
}

# Print a log line separator if the last thing we printed was not a log line separator.
# We use this to avoid printing two separators in a row.
sub print_log_line_separator_if_necessary {
	lock($output_lock);
	
	if (!$last_log_line_was_separator) {
		&output(0, $log_line_separator);
	}
	
	# Set the flag to show that we just printed a separator
	$last_log_line_was_separator = 1;
}

# Check the latency of the internet connection
# Returns one of:
#     LATENCY_BOTH_OK   - latency is OK in both directions
#     LATENCY_UL_BAD    - upload latency is bad, but download latency is OK
#     LATENCY_DL_BAD    - download latency is bad, but upload latency is OK
#     LATENCY_BOTH_BAD  - latency is bad in both directions
#     LATENCY_DOWN      - the connection is down
#     LATENCY_INVALID   - results are invalid
sub check_latency {
	my $dl_good_count   = 0;
	my $ul_good_count   = 0;
	my $ul_bad_count    = 0;
	my $dl_bad_count    = 0;
	my $timed_out_count = 0;

	my $ul_time_total      = 0;
	my $dl_time_total      = 0;
	my $ul_time_total_good = 0;
	my $dl_time_total_good = 0;

	my $ul_bw_total     = 0;
	my $dl_bw_total     = 0;
	my $ul_bw_total_bad = 0;
	my $dl_bw_total_bad = 0;

	my @valid_pings_ul = ();
	my @valid_pings_dl = ();
	my @bandwidth_usages_ul = ();
	my @bandwidth_usages_dl = ();
	
	my @detailed_results = ();
	
	my $need_summary_results = $latency_check_summary_interval != 0 || $log_bw_changes;
	my $need_detailed_results = $log_details_on_bw_changes || $debug_latency_check;

	# Take a copy of the results array so we don't block the receiver thread
	my @recent_results_copy;
	{
		lock(@recent_results);
		@recent_results_copy = @recent_results;
	}
	my $total_results = scalar(@recent_results_copy);

	# Update the bandwidth usage statistics
	&update_bandwidth_usage_stats(&get_wan_bytes());
	
	# Adaptive ICMP
	if ($icmp_adaptive && &is_icmp_warmup_done()) {
		my $return_bandwidth_results = 0;
		if (&is_connection_idle()) {
			# Connection down scenario is handled separately.
			# See &handle_connection_down() and &handle_connection_up().
			if (!$connection_down) {
				if (!&is_icmp_adaptive_idle()) {
					&set_icmp_adaptive_idle();
				}
				if ($icmp_adaptive_idle_suspend) {
					$return_bandwidth_results = 1;
				}
			}
		} elsif (&is_icmp_adaptive_idle()) {
			&set_icmp_adaptive_loaded();
			if ($icmp_adaptive_idle_suspend) {
				$return_bandwidth_results = 1;
			}
		}
		
		if ($return_bandwidth_results) {
			# If we reach here we have no ICMP results to examine, so just return a skeleton result
			# array containing only bandwidth usage figures. We also need to set the average
			# bandwidth usages to ensure that relaxation works correctly while we're idle.
			
			my ($ul_bw_ave, $dl_bw_ave) = &get_average_bandwidth_usage_since_last_latency_summary();
			&set_average_bandwidth_usage("upload", $ul_bw_ave);
			&set_average_bandwidth_usage("download", $dl_bw_ave);
				
			my @summary_results = (0, 0, 0, 0, $ul_bw_ave, $dl_bw_ave, 0, 0);
			return (LATENCY_OK, \@summary_results, \());
		}
	}

	if (scalar(@recent_results_copy) == 0) {
		# No results yet, so we can't assess latency
		if ($debug_latency_check) { &output(0, "LATENCY CHECK DEBUG: No results. Returning LATENCY_INVALID"); }
		return (LATENCY_INVALID, \(), \());
	}

	# Go through each result and check whether it was good, bad, or ugly
	RESULT: foreach my $result (@recent_results_copy) {
		my ($ip, $packet_id, $seq, $ul_time, $dl_time, $start_time, $finish_time) = split(/ /, $result);

		# Get bandwidth usages for the period(s) in which the ICMP request was sent and
		# the ICMP response was received
		my $ul_bw = &get_bandwidth_usage_at($start_time, "upload");
		my $dl_bw = &get_bandwidth_usage_at($finish_time, "download");

		# Extra boolean variables for detailed results array
		my $ul_good;
		my $dl_good;
		my $ul_strike = -1;
		my $dl_strike = -1;
		my $ignore_result = 0;

		# Check for strike conditions in both directions and record strikes if necessary.
		# We need to do this first because this might result in this reflector striking
		# out, in which case we want to ignore the result.
		# A strike is (by definition) a spurious bad result, so we mark the result as "good".
		if ($reflector_strikeout_threshold != 0) { # if $reflector_strikeout_threshold == 0 strikes are disabled
			if ($ul_time == ICMP_TIMED_OUT || $ul_time == ICMP_INVALID || $ul_time > $ul_max_idle_latency) {
				if ($ul_time == ICMP_INVALID || $ul_bw < $ul_bw_idle_threshold) {
					&record_strike($ip, $packet_id, $seq, ($finish_time + $reflector_strike_ttl), "upload");
					$ul_good = 1;
					$ul_strike = 1;
				} else {
					$ul_good = 0;
					$ul_strike = 0;
				}
			} else {
				$ul_good = 1;
				$ul_strike = 0;
			}
			if ($dl_time == ICMP_TIMED_OUT || $dl_time == ICMP_INVALID || $dl_time > $dl_max_idle_latency) {
				if ($dl_time == ICMP_INVALID || $dl_bw < $dl_bw_idle_threshold) {
					&record_strike($ip, $packet_id, $seq, ($finish_time + $reflector_strike_ttl), "download");
					$dl_good = 1;
					$dl_strike = 1;
				} else {
					$dl_good = 0;
					$dl_strike = 0;
				}
			} else {
				$dl_good = 1;
				$dl_strike = 0;
			}
		}

		# Check whether we should ignore this result
		
		# This first check needs to be done separately to minimise the scope of the %reflector_ips
		# lock, to make sure we're not holding it if/when we call &replace_reflector()
		{
			lock(%reflector_ips);
			if (!exists($reflector_ips{$ip})) {
				# This reflector has already been struckout and replaced.
				$ignore_result = 1;
			}
		}
		
		# Now do the rest of the checks, if necessary
		if (!$ignore_result) {
			if (&is_struckout($ip, "upload") || &is_struckout($ip, "download")) {
				# This reflector has just struckout. Replace it with a new one and ignore this result.
			
				# Get information about the strikes
				my $strike_summary = "";
				if (&is_struckout($ip, "upload")) {
					$strike_summary = "upload strikes at:";
					foreach my $strike (reverse(&get_strikes($ip, "upload"))) {
						if ($strike =~ /^\d+-\d+-(.+)$/) {
							$strike_summary .= " " . &format_time($1 - $reflector_strike_ttl);
						}
					}
				} else {
					$strike_summary = "download strikes at:";
					foreach my $strike (reverse(&get_strikes($ip, "download"))) {
						if ($strike =~ /^\d+-\d+-(.+)$/) {
							$strike_summary .= " " . &format_time($1 - $reflector_strike_ttl);
						}
					}
				}
				
				# Replace the reflector
				my $new_reflector_ip = &replace_reflector($ip);
				
				# Log a message
				&output(0, "BAD REFLECTOR: $ip replaced with $new_reflector_ip due to $strike_summary. Remaining pool: " . scalar(@reflector_pool));

				# Update the struckout count
				$struckout_count++;

				# Ignore this result
				$ignore_result = 1;
			} elsif ($ul_time == ICMP_INVALID && $dl_time == ICMP_INVALID) {
				# Reflector isn't struckout (yet), but this result was invalid
				$ignore_result = 1;
			}
		}
		
		if ($ignore_result) {
			if ($need_detailed_results) {
				my @result_details = (
					$start_time,
					$ip,
					$packet_id,
					$seq,
					$ul_time,
					$dl_time,
					$ul_bw,
					$dl_bw,
					$ul_good,
					$dl_good,
					$ul_strike,
					$dl_strike,
					$ignore_result
				);
		
				# Push the result array to the array containing all the detailed results
				push(@detailed_results, \@result_details);
			}
			
			$total_results--;
			
			next RESULT;
		}

		# If we reach here this result is valid, so let's take a look at it

		if ($ul_time == ICMP_TIMED_OUT && $dl_time == ICMP_TIMED_OUT) {
			$timed_out_count++;

			# Mark upload result as bad if bandwidth usage was significant
			if ($ul_bw >= $ul_bw_idle_threshold) {
				$ul_bad_count++;
				$ul_bw_total_bad += $ul_bw;
				$ul_good = 0;
			} else {
				$ul_good = 1;
			}				

			# Mark download result as bad if bandwidth usage was significant
			if ($dl_bw >= $dl_bw_idle_threshold) {
				$dl_bad_count++;
				$dl_bw_total_bad += $dl_bw;
				$dl_good = 0;
			} else {
				$dl_good = 1;
			}
		} else {
			# Check whether upload result was good or bad
			if ($ul_time > $ul_max_loaded_latency) {
				if ($ul_bw >= $ul_bw_idle_threshold) {
					$ul_bad_count++;
					$ul_bw_total_bad += $ul_bw;
					$ul_good = 0;
				} else {
					# No significant bandwidth usage, so record this as a "good" ping
					$ul_good_count++;
					$ul_time_total_good += $ul_time;
					$ul_good = 1;
				}
			} else {
				$ul_good_count++;
				$ul_time_total_good += $ul_time;
				$ul_good = 1;
			}
			
			# Check whether download result was good or bad
			if ($dl_time > $dl_max_loaded_latency) {
				if ($dl_bw >= $dl_bw_idle_threshold) {
					$dl_bad_count++;
					$dl_bw_total_bad += $dl_bw;
					$dl_good = 0;
				} else {
					# No significant bandwidth usage, so record this as a "good" ping
					$dl_good_count++;
					$dl_time_total_good += $dl_time;
					$dl_good = 1;
				}
			} else {
				$dl_good_count++;
				$dl_time_total_good += $dl_time;
				$dl_good = 1;
			}
			
			if ($need_summary_results) {
				push(@valid_pings_ul, $ul_time);
				push(@valid_pings_dl, $dl_time);
			}
		}

		push(@bandwidth_usages_ul, $ul_bw);
		push(@bandwidth_usages_dl, $dl_bw);
		
		# Create an array containing the details for this result
		if ($need_detailed_results) {
			my @result_details = (
				$start_time,
				$ip,
				$packet_id,
				$seq,
				$ul_time,
				$dl_time,
				$ul_bw,
				$dl_bw,
				$ul_good,
				$dl_good,
				$ul_strike,
				$dl_strike,
				$ignore_result
			);
		
			# Push the result array to the array containing all the detailed results
			push(@detailed_results, \@result_details);
		}
	} # end of foreach on @recent_results_copy

	# Check that we still have enough results now that the results
	# from any disregarded reflectors have been excluded
	if ($total_results == 0) {
		if ($debug_latency_check) { &output(0, "LATENCY CHECK DEBUG: No results after excluding bad reflectors. Returning LATENCY_INVALID"); }
		
		# Note - return @detailed_results because this might contain
		# useful information about the ignored results
		return (LATENCY_INVALID, \(), \@detailed_results);
	}

	# Update the bandwidth steps
	&update_bw_steps("upload", $ul_time_total_good, $ul_bw_total_bad, $ul_good_count, $ul_bad_count);
	&update_bw_steps("download", $dl_time_total_good, $dl_bw_total_bad, $dl_good_count, $dl_bad_count);

	# Now work out the overall result for each direction

	# If we had more than $max_bad_pings bad pings, latency is marked as bad.
	# Otherwise, latency is marked as ok.
	my $result_ul = ($ul_bad_count > $max_bad_pings) ? LATENCY_BAD : LATENCY_OK;
	my $result_dl = ($dl_bad_count > $max_bad_pings) ? LATENCY_BAD : LATENCY_OK;

	if ($timed_out_count == $total_results) {
		# If we reach here, all of the recent results timed out
		# The connection might be down...

		if ($total_results > $max_bad_pings || $connection_down) {
			# Sustained unresponsiveness, or the connection is already marked as down
			$result_ul = LATENCY_DOWN;
			$result_dl = LATENCY_DOWN;
		} else {
			# The connection is not marked as down and the number of unresponsive pings
			# hasn't exceeded $max_bad_pings yet.
			# This could be a transient glitch, so return LATENCY_OK for now.
			$result_ul = LATENCY_OK;
			$result_dl = LATENCY_OK;
		}
	}

	# Now work out the overall result
	my $overall_result = -1;
	if ($result_ul == LATENCY_OK && $result_dl == LATENCY_OK) {
		$overall_result = LATENCY_BOTH_OK;
	} elsif ($result_ul == LATENCY_BAD && $result_dl == LATENCY_OK) {
		$overall_result = LATENCY_UL_BAD;
	} elsif ($result_ul == LATENCY_OK && $result_dl == LATENCY_BAD) {
		$overall_result = LATENCY_DL_BAD;
	} elsif ($result_ul == LATENCY_BAD && $result_dl == LATENCY_BAD) {
		$overall_result = LATENCY_BOTH_BAD;
	} elsif ($result_ul == LATENCY_DOWN || $result_dl == LATENCY_DOWN) {
		# We will have recorded some spurious strikes, so we'll clear them.
		# This will also clear any legitimate strikes that were recorded
		# before the connection went down, but we (currently) have no way
		# to only remove the strikes recorded during this latest cycle,
		# and this situation will be rare anyway, so this is good enough.
		&clear_all_strikes();

		$overall_result = LATENCY_DOWN;
	}

	# Get and store the average bandwidth usage for each direction
	# This is used when assessing if/how to change the SQM bandwidth
	my $ul_bw_ave = sum(@bandwidth_usages_ul)/scalar(@bandwidth_usages_ul);
	my $dl_bw_ave = sum(@bandwidth_usages_dl)/scalar(@bandwidth_usages_dl);
	&set_average_bandwidth_usage("upload", $ul_bw_ave);
	&set_average_bandwidth_usage("download", $dl_bw_ave);
	
	my @summary_results = ();
	if ($need_summary_results) {
		@summary_results = (
			$total_results,
			$ul_bad_count,
			$dl_bad_count,
			$timed_out_count,
			$ul_bw_ave,
			$dl_bw_ave,
			\@valid_pings_ul,
			\@valid_pings_dl
		);
	}
				
	return ($overall_result, \@summary_results, \@detailed_results);
}

# Given a result from &check_latency(), check whether latency is bad for the
# specified direction. Returns 1 is latency is OK, 0 if latency is not OK.
sub is_latency_ok {
	my ($latency_result, $direction) = @_;

	&check_direction($direction);

	if ($latency_result == LATENCY_BOTH_BAD) {
		return 0;
	} elsif ($direction eq "download" && $latency_result == LATENCY_DL_BAD) {
		return 0;
	} elsif ($direction eq "upload" && $latency_result == LATENCY_UL_BAD) {
		return 0;
	} else {
		return 1;
	}
}

# Clear all recent ICMP latency results and all pending ICMP requests
sub clear_latency_results {
	lock(%icmp_timeout_times);
	lock(%icmp_sent_times);
	lock(@recent_results);	
	
	%icmp_timeout_times = ();
	%icmp_sent_times = ();
	@recent_results = ();

	if ($debug_latency_check) { &output(0, "LATENCY CHECK DEBUG: Latency results cleared"); }
}

# Create a new ICMP socket
# Returns the file descriptor
sub create_icmp_socket {
	my $fd;
	socket($fd, AF_INET, SOCK_RAW, ICMP_PROTOCOL) || die("ICMP socket error - $!");
	return $fd;
}

# Send an ICMP timestamp request to the specified IP address, on the specified socket
# Returns the packet ID and sequence number for the message that was sent
sub send_icmp_timestamp_request {
	my ($ip, $fd) = @_;

	# Get the packet ID and sequence number for this socket
	my $id = &get_packet_id($ip);
	my $seq = &get_next_seq($ip);

	# Get the number of milliseconds since midnight UTC
	my $ms_since_midnight = &get_ms_since_midnight();

	# Construct the ICMP message
	my $msg = pack(ICMP_TIMESTAMP_STRUCT, ICMP_TIMESTAMP, 0, 0, $id, $seq, $ms_since_midnight, 0, 0);

	# Calculate the checksum
	my $checksum = &get_checksum($msg);

	# Add the checksum to the message
	$msg = pack(ICMP_TIMESTAMP_STRUCT, ICMP_TIMESTAMP, 0, $checksum, $id, $seq, $ms_since_midnight, 0, 0);

	# Send the message
	send($fd, $msg, 0, pack_sockaddr_in(0, inet_aton($ip)));
	if ($debug_icmp) {
		&output(0, sprintf(
			"ICMP DEBUG: SEND:                                 ip=%-15s id=%-5s seq=%-5s",
			$ip,
			$id,
			$seq
		));
	}

	# Update counters
	{
		lock($icmp_request_count);
		lock($icmp_request_bytes);
		$icmp_request_count++;
		$icmp_request_bytes += 20;
	}

	# Return the ID and sequence number
	return ($id, $seq);
}

# Handle an ICMP timestamp reply packet
sub handle_icmp_reply {
	my ($from_ip, $recv_msg) = @_;

	# Get the current timestamp
	my $icmp_end = &get_ms_since_midnight();

	# Grab the end time to use for bandwidth calculation later on
	my $icmp_received = gettimeofday();

	# This will be populated from the data we stored earlier
	my $icmp_sent;

	my $reply_received = 0;
	my $reply_id = -1;
	my $reply_seq = -1;
	my $icmp_orig = -1;
	my $icmp_recv = -1;
	my $icmp_tran = -1;
	my $pending_requests = -1;

	my %bandwidth_usage;

	if (length($recv_msg) < ICMP_PAYLOAD_OFFSET + 20) {
		# Not a valid timestamp reply packet.
		return;
	}

	($reply_id, $reply_seq, $icmp_orig, $icmp_recv, $icmp_tran) = unpack("n2 N3", substr($recv_msg, ICMP_PAYLOAD_OFFSET + 4, 16));

	my $reply_sig = "$from_ip $reply_id $reply_seq";

	{
		lock(%icmp_timeout_times);
		lock(%icmp_sent_times);

		# Check whether this ICMP reply corresponds to one of our requests
		if (exists($icmp_timeout_times{$reply_sig})) {
			# Get the start time for this ICMP request
			$icmp_sent = $icmp_sent_times{$reply_sig};

			# Remove the data associated with this request
			delete($icmp_timeout_times{$reply_sig});
			delete($icmp_sent_times{$reply_sig});
			
			# We'll continue processing later on to avoid holding the hash locks for longer than necessary
			$reply_received = 1;
		}

		$pending_requests = scalar(keys(%icmp_timeout_times));
	} 

	if ($reply_received) {
		my @corrected_icmp_timestamps = &correct_icmp_timestamps($from_ip, $reply_id, $reply_seq, $icmp_orig, $icmp_recv, $icmp_tran, $icmp_end);

		my $ul_time;
		my $dl_time;
		my $rtt;
		my $offset;
		
		if (scalar(@corrected_icmp_timestamps) == 0) {
			# The timestamps could not be corrected.
			$ul_time = ICMP_INVALID;
			$dl_time = ICMP_INVALID;
			$rtt = ICMP_INVALID;
			$offset = &get_icmp_offset($from_ip);
		} else {
			# The timestamps were corrected and look ok
			($icmp_orig, $icmp_recv, $icmp_tran, $icmp_end, $offset) = @corrected_icmp_timestamps;
		
			# Calculate the request/response times
			$ul_time = $icmp_recv - $icmp_orig;
			$dl_time = $icmp_end - $icmp_tran;
			$rtt = $icmp_end - $icmp_orig;
		}
		
		if ($debug_icmp) {
			&output(0, sprintf(
				"ICMP DEBUG: RECEIVE: CORRECTED: sent=%s ip=%-15s id=%-5s seq=%-5s orig=%-10s recv=%-10s tran=%-10s end=%-10s offset=%-11s ul=%-5s dl=%-5s rtt=%-5s pending=%-4s",
				&format_time($icmp_sent),
				$from_ip,
				$reply_id,
				$reply_seq,
				$icmp_orig,
				$icmp_recv,
				$icmp_tran,
				$icmp_end,
				$offset,
				$ul_time,
				$dl_time,
				$rtt,
				$pending_requests
			));
		}

		# Add result to the shared array
		{
			lock(@recent_results);
			push(@recent_results, join(" ", $from_ip, $reply_id, $reply_seq, $ul_time, $dl_time, $icmp_sent, $icmp_received));
			if (scalar(@recent_results) > $max_recent_results) {
				shift(@recent_results);
			}
		}
		
		# Update counters
		{
			lock($icmp_response_count);
			lock($icmp_response_bytes);
			$icmp_response_count++;
			$icmp_response_bytes += 20;
		}
	}
	
	return $reply_received;
}

# There are a variety of situations in which ICMP timestamps
# can be inconsistent. This subroutine attempts to handle those
# situations and correct the timestamps so we can calculate
# accurate request and response times. The corrected timestamps
# are returned along with the reflector's current offset.
sub correct_icmp_timestamps {
	my ($reflector_ip, $id, $seq, $icmp_orig, $icmp_recv, $icmp_tran, $icmp_end) = @_;

	# Calculate request and response times based on the raw timestamps
	my $ul_time = $icmp_recv - $icmp_orig;
	my $dl_time = $icmp_end - $icmp_tran;

	if ($debug_icmp) {
		&output(0, sprintf(
			"ICMP DEBUG: RECEIVE:       RAW:                   ip=%-15s id=%-5s seq=%-5s orig=%-10s recv=%-10s tran=%-10s end=%-10s                                      rtt=%-5s",
			$reflector_ip,
			$id,
			$seq,
			$icmp_orig,
			$icmp_recv,
			$icmp_tran,
			$icmp_end,
			($icmp_end - $icmp_orig)
		));
	}
	
	# Get the current offset for this reflector. The offset
	# attempts to compensate for a stable(ish) difference
	# between the reflector's timestamps and our timestamps.
	# See the comments for &update_icmp_offset().
	my $offset_updated = 0;
	my $offset = &get_icmp_offset($reflector_ip);
	if (!defined($offset)) {
		# This must be the first time we've used this reflector
		# Calculate the offset based on the raw results
		$offset = &update_icmp_offset($reflector_ip, $ul_time, $dl_time);
	}
	
	# Apply the offset to the results
	$ul_time += $offset;
	$dl_time -= $offset;
	
	# Regardless of what the reflector's timestamp is based on,
	# both our timer and the reflector's will be reset to zero at
	# some point during the day, which will cause problems if
	# our timer has been reset but the reflector's hasn't, or
	# vice versa. This is most likely to happen around midnight
	# UTC, but could happen at any time if a reflector's timer is
	# relative to a time other than midnight UTC.
	#
	# There are four scenarios that need action:
	#
	# 1. Our timer has been reset to zero before the request was
	#    sent, but the reflector's hasn't
	# 2. The reflector's timer has been reset to zero before the
	#    was received, but ours hasn't
	# 3. Our timer resets to zero between sending the request
	#    and receiving the response
	# 4. The reflector's timer resets to zero between receiving
	#    the request and sending the response
	#
	# The following code checks whether there is a large disparity
	# between this result and the previous result(s) for this
	# reflector. If there is a large disparity, it might be for one
	# of the reasons listed above, in which case we can correct it
	# by adding a day's worth of millseconds to the appropriate
	# timestamps.
	#
	# If the result still looks weird after trying to correct for
	# timer resets it means the reflector is probably returning
	# nonsensical timestamps (i.e. not based on a timer at all).

	# First, check whether the request/response times look sensible
	# after applying the current offset for this reflector.
	# If either of them is negative or greater than our ICMP timeout
	# we might have a problem.
	my $icmp_timeout_ms = $icmp_timeout * 1000;
	if (
		$ul_time < 0 || $ul_time > $icmp_timeout_ms ||
		$dl_time < 0 || $dl_time > $icmp_timeout_ms
	) {
		# Record the pre-correction timestamps
		my $icmp_orig_before = $icmp_orig;
		my $icmp_recv_before = $icmp_recv;
		my $icmp_tran_before = $icmp_tran;
		my $icmp_end_before  = $icmp_end;

		# The following code effectively checks whether the offset of the 
		# reflector's timestamps has changed by more than $icmp_timeout
		# in either direction. This should only happen if the ICMP timestamps
		# are excessively variable (i.e. nonsensical) or a timer reset has
		# occurred as described above.

		if ($icmp_recv + $offset + $icmp_timeout_ms < $icmp_orig) {
			# The reflector's timer might have been reset before it received
			# the request, but ours was not
			if ($debug_icmp_correction) { &output(0, "ICMP DEBUG: RECEIVE:   WARNING: recv timestamp for \"$reflector_ip $id $seq\" too small after applying offet of $offset. Attempting to correct..."); }
			$icmp_recv += 86400000;
			$icmp_tran += 86400000;
		} elsif ($icmp_tran + $offset + $icmp_timeout_ms < $icmp_orig) {
			# The reflector's timer might have been reset before it sent the
			# response, but ours was not
			if ($debug_icmp_correction) { &output(0, "ICMP DEBUG: RECEIVE:   WARNING: tran timestamp for \"$reflector_ip $id $seq\" too small after applying offet of $offset. Attempting to correct..."); }
			$icmp_tran += 86400000;
		}
			
		if ($icmp_recv + $offset > $icmp_orig + $icmp_timeout_ms) {
			# Our timer might have been reset before we sent the request,
			# but the reflector's wasn't
			if ($debug_icmp_correction) { &output(0, "ICMP DEBUG: RECEIVE:   WARNING: orig timestamp for \"$reflector_ip $id $seq\" too small after applying offset of $offset. Attempting to correct..."); }
			$icmp_orig += 86400000;
			$icmp_end += 86400000;
		} elsif ($icmp_tran + $offset > $icmp_end + $icmp_timeout_ms) {
			# Our timer might have been reset before the reflector sent the
			# response, but the reflector's wasn't
			if ($debug_icmp_correction) { &output(0, "ICMP DEBUG: RECEIVE:   WARNING: end timestamp for \"$reflector_ip $id $seq\" too small after applying offet of $offset. Attempting to correct..."); }
			$icmp_end += 86400000;
		}
		
		# If we tried to correct this result let's see if it worked.
		# If we didn't attempt a correction (i.e. the disparity wasn't large enough)
		# we'll just fall through and adjust the offset based on the new result.
		if (
			$icmp_orig_before != $icmp_orig ||
			$icmp_recv_before != $icmp_recv ||
			$icmp_tran_before != $icmp_tran ||
			$icmp_end_before != $icmp_end
		) {
			# Recalculate the request/response times again and see if
			# they look more sensible now.
			$ul_time = $icmp_recv - $icmp_orig + $offset;
			$dl_time = $icmp_end - $icmp_tran - $offset;
			if (
				$ul_time < 0 || $ul_time > $icmp_timeout_ms ||
				$dl_time < 0 || $dl_time > $icmp_timeout_ms
			) {
				# The times still look weird. Nothing else we can try
				# so just discard this result.
				
				# It's possible that the offset has changed legitimately, for example
				# due a clock update either on our side or the reflector's side.
				# So we'll update the offset based on the current results (before we
				# tried to correct them). If this was a legitimate offset change the
				# results should be ok the next time this reflector is used.
				&update_icmp_offset($reflector_ip, ($icmp_recv_before - $icmp_orig_before), ($icmp_end_before - $icmp_tran_before));
				
				if ($debug_icmp_correction) { 
					&output(0, 
						"ICMP DEBUG: RECEIVE:   WARNING: Timestamps could not be corrected for \"$reflector_ip $id $seq\" using current offset of $offset\n" .
						sprintf(
							"ICMP DEBUG: RECEIVE:            Before: ip=%-15s orig=%-10s recv=%-10s tran=%-10s end=%-10s ul_time=%-11s dl_time=%-11s rtt=%d\n",
							$reflector_ip,
							$icmp_orig_before,
							$icmp_recv_before,
							$icmp_tran_before,
							$icmp_end_before,
							($icmp_recv_before - $icmp_orig_before),
							($icmp_end_before - $icmp_tran_before),
							($icmp_end_before - $icmp_orig_before)
						) .
						sprintf(
							"ICMP DEBUG: RECEIVE:             After: ip=%-15s orig=%-10s recv=%-10s tran=%-10s end=%-10s ul_time=%-11s dl_time=%-11s rtt=%d",
							$reflector_ip,
							$icmp_orig,
							$icmp_recv,
							$icmp_tran,
							$icmp_end,
							$ul_time,
							$dl_time, 
							($icmp_end - $icmp_orig)
						)
					);
				}
			
				# Return an empty array
				return ();
			}

			# If we reach here it looks like our attempt to correct the large disparity worked!
		
			if ($debug_icmp_correction) { 
				&output(0, 
					"ICMP DEBUG: RECEIVE:   WARNING: Local and/or remote timer reset detected and corrected for \"$reflector_ip $id $seq\":\n" .
					sprintf(
						"ICMP DEBUG: RECEIVE:            Before: ip=%-15s orig=%-10s recv=%-10s tran=%-10s end=%-10s ul_time=%-11s dl_time=%-11s rtt=%d\n",
						$reflector_ip,
						$icmp_orig_before,
						$icmp_recv_before,
						$icmp_tran_before,
						$icmp_end_before,
						($icmp_recv_before - $icmp_orig_before),
						($icmp_end_before - $icmp_tran_before),
						($icmp_end_before - $icmp_orig_before)
					) .
					sprintf(
						"ICMP DEBUG: RECEIVE:             After: ip=%-15s orig=%-10s recv=%-10s tran=%-10s end=%-10s ul_time=%-11s dl_time=%-11s rtt=%d",
						$reflector_ip,
						$icmp_orig,
						$icmp_recv,
						$icmp_tran,
						$icmp_end,
						$ul_time,
						$dl_time, 
						($icmp_end - $icmp_orig)
					)
				);
			}
		}
	}
	
	# If we reach here the result is acceptable, either before or after correction.
	
	# Update the offset based on the (corrected) ICMP timestamps, and apply it
	$offset = &update_icmp_offset($reflector_ip, ($icmp_recv - $icmp_orig), ($icmp_end - $icmp_tran));
	$icmp_recv += $offset;
	$icmp_tran += $offset;
	
	return ($icmp_orig, $icmp_recv, $icmp_tran, $icmp_end, $offset);
}

# Go through the requests hash and clear any requests that have timed out
sub process_icmp_timeouts {
	lock(%icmp_timeout_times);
	lock(%icmp_sent_times);

	foreach my $request_sig (keys(%icmp_timeout_times)) {
		my $current_time = gettimeofday();
		if ($icmp_timeout_times{$request_sig} <= $current_time) {
			my ($request_ip, $request_id, $request_seq) = split(/ /, $request_sig);

			# Set the received time and get the sent time for this timed out request
			my $icmp_received = gettimeofday();
			my $icmp_sent = $icmp_sent_times{$request_sig};
			
			if ($debug_icmp || $debug_icmp_timeout) {
				&output(0, sprintf(
					"ICMP DEBUG: RECEIVE: TIMED OUT: sent=%s ip=%-15s id=%-5s seq=%-5s",
					&format_time($icmp_sent),
					$request_ip,
					$request_id,
					$request_seq
				));
			}

			# Add timed out result to the shared array
			{
				lock(@recent_results);
				push(@recent_results, join(" ", $request_ip, $request_id, $request_seq, ICMP_TIMED_OUT, ICMP_TIMED_OUT, $icmp_sent, $icmp_received));
				if (scalar(@recent_results) > $max_recent_results) {
					shift(@recent_results);
				}
			}
			
			# Remove the data associated with this request
			delete($icmp_timeout_times{$request_sig});
			delete($icmp_sent_times{$request_sig});
		}
	}
}

# Get the packet ID for the specified reflector IP
sub get_packet_id {
	my ($ip) = @_;

	lock(%reflector_packet_ids);

	# If we don't yet have an ID for this reflector, create
	# a new one and make sure it's not a duplicate
	if (!exists($reflector_packet_ids{$ip})) {
		my $id = int(rand(65535));
		while (grep(/$id/, values(%reflector_packet_ids))) {
			$id = int(rand(65535));
		}
		$reflector_packet_ids{$ip} = $id;
	}

	return $reflector_packet_ids{$ip};
}

# Get the next sequence ID for the specified IP and socket
sub get_next_seq {
	my ($ip) = @_;

	lock(%reflector_seqs);

	if (exists($reflector_seqs{$ip})) {
		$reflector_seqs{$ip} = ($reflector_seqs{$ip} + 1) % 65536;
	} else {
		$reflector_seqs{$ip} = 1
	}

	return $reflector_seqs{$ip};
}

# Get the number of milliseconds since midnight UTC
sub get_ms_since_midnight {
	# Today's date (UTC)
	my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday) = gmtime();
	
	# Epoch time for 00:00 this morning (UTC)
	my $midnight_utc_ms = timegm(0, 0, 0, $mday, $mon, $year) * 1000;

	# Return the difference between now and midnight UTC
	return &round(gettimeofday() * 1000) - $midnight_utc_ms;
}

# Subroutine to calculate an internet checksum (based on the implementation in Net::Ping.pm)
sub get_checksum {
	my ($msg) = @_;

	my $len_msg = length($msg);
	my $num_short = int($len_msg / 2);
	my $chk = 0;
  
	foreach my $short (unpack("n$num_short", $msg)) {
		$chk += $short;
	}

	# Add the odd byte in
	$chk += (unpack("C", substr($msg, $len_msg - 1, 1)) << 8) if $len_msg % 2;

	$chk = ($chk >> 16) + ($chk & 0xffff);      # Fold high into low

	return(~(($chk >> 16) + $chk) & 0xffff);    # Again and complement
}

# ICMP type 13 timestamps should be based on the number of milliseconds
# since midnight UTC. However, this isn't mandatory and they can be based
# on anything they like.
#
# Even if the timestamps *are* based on the number of milliseconds since
# midnight UTC, the request and response times we calculate will only be
# accurate if our system clock is precisely in sync with the reflector's
# system clock. This will normally not be the case. When the NTP daemon
# has had 12-24 hours to synchronize with an NTP server the times will
# be pretty close, probably to within 5-10 milliseconds, but they can be
# hundreds of millseconds out when we first boot up.
#
# Either way, any difference between our timer and the reflector's timer
# will cause our calculated request and response times to be inflated,
# reduced, or even negative. However, as long as the difference is
# relatively consistent we can address this by applying an offset to
# compensate for it.
#
# Obviously we can't know what the difference between the timers is,
# but we can estimate it based on the minimum possible request/response
# time. We use the lowest half-round-trip-time we've ever seen. If a
# request/response is lower than this value, we calculate the number of
# milliseconds required to bump it up to the minimum, and apply this
# offset to both the request and the response. We add the offset to the
# request time, and subtract it from the response time, and the offset
# can be positive or negative. The minimum response/request time and
# offset for each target host are stored in hashes and adjusted when
# necessary.

# Get the current ICMP offset for the specified reflector
# Returns an undefined value if there's no offset for this reflector
sub get_icmp_offset {
	my ($reflector_ip) = @_;

	lock(%reflector_offsets);

	return $reflector_offsets{$reflector_ip};
}

# Get the current ICMP offset for the specified reflector after updating
# it based on the new request and response times provided
sub update_icmp_offset {
	my ($reflector_ip, $request_time, $response_time) = @_;

	lock(%reflector_offsets);

	my $minimum_half_rtt = int(&get_icmp_minimum_rtt($reflector_ip, $request_time + $response_time) / 2);

	# First ping for this reflector. Start with an offset of 0.
	if (!exists($reflector_offsets{$reflector_ip})) { $reflector_offsets{$reflector_ip} = 0; }

	# Get the current offset
	my $offset = $reflector_offsets{$reflector_ip};
	
	# Adjust the offset if necessary
	if ($request_time + $offset < $minimum_half_rtt) {
		$offset = $minimum_half_rtt - $request_time;
		if ($debug_offsets) {
			&output(0, "OFFSET DEBUG: $reflector_ip offset adjusted: " . $reflector_offsets{$reflector_ip} . " -> $offset (request + offset = " . ($request_time + $reflector_offsets{$reflector_ip}) . ", min = $minimum_half_rtt)");
		}		
		$reflector_offsets{$reflector_ip} = $offset;
	} elsif ($response_time - $offset < $minimum_half_rtt) {
		$offset = $response_time - $minimum_half_rtt;
		if ($debug_offsets) {
			&output(0, "OFFSET DEBUG: $reflector_ip offset adjusted: " . $reflector_offsets{$reflector_ip} . " -> $offset (response - offset = " . ($response_time - $reflector_offsets{$reflector_ip}) . ", min = $minimum_half_rtt)");
		}
		$reflector_offsets{$reflector_ip} = $offset;
	}

	return $offset;
}

# Returns the smallest RTT ever seen for the specified reflector, including
# the new RTT sample provided.
sub get_icmp_minimum_rtt {
	my ($reflector_ip, $new_sample) = @_;

	lock(%reflector_minimum_rtts);
	
	if (!exists($reflector_minimum_rtts{$reflector_ip}) ||	$new_sample < $reflector_minimum_rtts{$reflector_ip}) {
		if ($debug_offsets) {
			&output(0, "OFFSET DEBUG: $reflector_ip new minimum RTT: " . $new_sample . " ms");
		}
		$reflector_minimum_rtts{$reflector_ip} = $new_sample;
	}
	
	return $reflector_minimum_rtts{$reflector_ip};
}

# Calculate and return the jitter from a set of values.
# Jitter is the average difference between each value and
# the previous value.
sub get_jitter {
	my (@values) = @_;

	my $jitter = 0;
	my $previous = -1;
	foreach my $current (@values) {
		if ($previous != -1) {
			$jitter += abs($current - $previous) / (scalar(@values) - 1);
		}
		$previous = $current;
	}

	return $jitter;
}

# Update the bandwidth increase/decrease steps for the specified direction. Increase steps
# are calculated based on the average good ping time as follows:
#
#   ([ping threshold] - [average good ping]) * $increase_factor
#
# Increase steps are also tapered as we approach the maximum bandwidth.
#
# Decrease steps are calculated based on the average bandwidth usage at the times when bad
# pings were detected:
#
#   ([current bandwidth] - [average bad bandwidth usage]) / [current bandwidth] * 100
#
sub update_bw_steps {
	my ($direction, $good_ping_total, $bad_bw_usage_total, $good_ping_count, $bad_ping_count) = @_;

	if ($bad_ping_count > 0) {
		# We had some bad pings. Calculate and store the average bandwidth usage when the bad pings were detected.
		my $average_bad_bw_usage = $bad_bw_usage_total / $bad_ping_count;
		&set_average_bad_bandwidth_usage($direction, $average_bad_bw_usage);

		# Calculate the new target bandwidth
		my $target_bandwidth = $average_bad_bw_usage - ($average_bad_bw_usage * ($decrease_overshoot_pc / 100));

		# Calculate the percentage decrease required to attain the target bandwidth
		my $decrease_step_pc = ((&get_current_bandwidth($direction) - $target_bandwidth) / &get_current_bandwidth($direction)) * 100;

		# Make sure that the decrease step is at least $decrease_min_pc
		# This covers the rare case where the calculated decrease step is negative.
		# This can happen if more packets arrive on the WAN interface than allowed by
		# the SQM limit.
		if ($decrease_step_pc < $decrease_min_pc) {
			$decrease_step_pc = $decrease_min_pc;
		}

		# Set the steps 
		&set_decrease_step_pc($direction, $decrease_step_pc);
		&set_increase_step_pc($direction, 0);
	} elsif ($good_ping_count > 0) {
		# We had no bad pings. Calculate the average good ping time.
		my $average_good_latency = $good_ping_total / $good_ping_count;
		&set_average_good_latency($direction, $average_good_latency);

		# Calculate an increase step based on the average good ping time
		my $increase_step_pc_from_ping = abs(&get_max_loaded_latency($direction) - $average_good_latency) * $increase_factor;

		# Calculate an increase step based purely on our promixity to the maximum bandwidth
		my $increase_step_pc_from_bw = (1 - (&get_current_bandwidth($direction) / &get_max_bandwidth($direction))) * $increase_max_pc;
		if ($increase_step_pc_from_bw < $increase_min_pc) {
			$increase_step_pc_from_bw = $increase_min_pc;
		}

		# Choose the smallest of the two values calculated above
		my $increase_step_pc = $increase_step_pc_from_ping < $increase_step_pc_from_bw ? $increase_step_pc_from_ping : $increase_step_pc_from_bw;

		# Set the steps
		&set_increase_step_pc($direction, $increase_step_pc);
		&set_decrease_step_pc($direction, 0);
	} else {
		# We somehow had no good or bad pings :o/
		&set_increase_step_pc($direction, 0);
		&set_decrease_step_pc($direction, 0);
	}
}

# Set the connection down flag if necessary and generate an appropriate log message
# Returns 1 if the connection state has changed from up -> down, or 0 otherwise.
sub handle_connection_down {
	my ($summary_results_array_ref, $detailed_results_array_ref) = @_;
	
	if (!$connection_down) {
		# Connection has just gone down. Print detailed latency results to the log file
		if ($log_bw_changes || $log_details_on_bw_changes) { &print_log_line_separator_if_necessary(); }
		if ($log_details_on_bw_changes || $debug_latency_check) { &print_latency_results_details(@{$detailed_results_array_ref}); }
		if ($log_bw_changes) { &print_latency_results_summary(@{$summary_results_array_ref}); }
		
		# Send high priority alert to the syslog
		&output(1, "Internet connection appears to be down.", 1);
		if ($debug_bw_changes) { &output(0, "Setting connection down flag"); }
		$connection_down = 1;

		if ($icmp_adaptive) {
			if ($icmp_adaptive_idle_suspend) {
				if ($debug_icmp_adaptive) { &output(0, "ICMP ADAPTIVE DEBUG: Setting ICMP interval to 1s"); }
				# If we suspended the threads we would never know when the
				# connection comes back up, so just set ICMP interval to 1s
				$icmp_interval = 1;
			} else {
				# Set Adaptive ICMP to idle mode if not idling already
				if (!&is_icmp_adaptive_idle()) {
					&set_icmp_adaptive_idle();
				}
			}
		}
		
		# Indicate that connection state has changed
		return 1;
	} else {
		# Indicate that connection state has not changed
		return 0;
	}
}

# Unset the connection down flag and generate an appropriate log message if necessary
# Returns 1 if the connection state has changed from down -> up, or 0 otherwise.
sub handle_connection_up {
	my ($summary_results_array_ref, $detailed_results_array_ref) = @_;
	
	if ($connection_down) {
		# Connection has just come back up. Print detailed latency results to the log file
		if ($log_bw_changes || $log_details_on_bw_changes) { &print_log_line_separator_if_necessary(); }
		if ($log_details_on_bw_changes || $debug_latency_check) { &print_latency_results_details(@{$detailed_results_array_ref}); }
		if ($log_bw_changes) { &print_latency_results_summary(@{$summary_results_array_ref}); }
		
		# Send high priority alert to the syslog
		&output(1, "Internet connection is back up", 1);
		if ($debug_bw_changes) { &output(0, "Unsetting connection down flag"); }
		$connection_down = 0;
		
		if ($icmp_adaptive) {
			if ($icmp_adaptive_idle_suspend) {
				# Reset ICMP interval to $icmp_interval_loaded
				if ($debug_icmp_adaptive) { &output(0, "ICMP ADAPTIVE DEBUG: Setting ICMP interval to $icmp_interval_loaded" . "s"); }
				$icmp_interval = $icmp_interval_loaded;
			}
		}

		# Reset the bandwidth to the standard values if necessary.
		# Either way the recent latency results will be cleared so
		# we start from scratch on the next cycle.
		if (!&is_bandwidth_at_std("upload") || !&is_bandwidth_at_std("download")) {
			&output(0, "Resetting bandwidth after internet connection outage");
			&reset_bandwidth();
		} else {
			&clear_latency_results();
		}
		
		# Indicate that connection state has changed
		return 1;
	} else {
		# Indicate that connection state has not changed
		return 0;
	}
}

# Check that the specified direction is valid.
# It must be either "download" or "upload".
sub check_direction {
	my ($direction) = @_;

	if (!defined($direction) || ($direction ne "download" && $direction ne "upload")) {
		my $caller = (caller(1))[3] . "()";
		&fatal_error("Bad direction specified in $caller: $direction");
	}
}

# Runs a system command and returns STDOUT and STDERR in a single string
sub run_sys_command {
	my ($command) = @_;
	
	# The sender and receiver threads need to be blocked at safe points
	# before we fork, otherwise we can deadlock.
	my $need_to_resume_icmp_threads = 0;
	if (!&are_icmp_threads_suspended()) {
		&suspend_icmp_threads();
		$need_to_resume_icmp_threads = 1;
	}
	
	if ($debug_sys_commands) { &output(0, "SYSCOMMAND DEBUG: Running system command: \"$command\""); }
		
	my $result = `$command 2>&1`;
	chomp($result);
		
	if ($debug_sys_commands) { &output(0, "SYSCOMMAND DEBUG: System command result: \"$result\""); }
	
	if ($need_to_resume_icmp_threads) {
		&resume_icmp_threads();
	}
	
	return $result;
}

# Sets the type and time of the last change for the specified direction
sub set_last_change {
	my ($direction, $change) = @_;
	
	&check_direction($direction);

	my $current_time = gettimeofday();

	if ($debug_bw_changes) { &output(0, "Setting last change for $direction: $change @ $current_time"); }

	$last_change{$direction} = $change;
	$last_change_time{$direction} = $current_time;
}	

# Returns the last change type for the specified direction
sub get_last_change_type {
	my ($direction) = @_;

	&check_direction($direction);

	return $last_change{$direction};
}

# Returns the number of seconds since the last change for the specified direction
sub time_since_last_change {
	my ($direction) = @_;
	
	&check_direction($direction);
	
	return (gettimeofday() - $last_change_time{$direction})
}

# Round a value to the nearest integer
# using half-up rounding
sub round {
	my ($value) = @_;
	return int($value + 0.5);
}

# Round a value to the next highest integer
sub round_up {
	my ($value) = @_;
	return int($value + 1);
}

# Get a formatted localtime string for the current time,
# including milliseconds
sub localtime_millis {
	my ($secs, $millis) = &get_rounded_secs_and_millis(scalar(gettimeofday()));

	my @localtime = localtime($secs);
	my $date_time = strftime("%a %b %e %H:%M:%S", @localtime);
	my $year = strftime("%Y", @localtime);
	
	return "$date_time.$millis $year";
}

# Format a timestamp to HH:mm:ss.SSS
sub format_time {
	my ($time) = @_;
	
	my ($secs, $millis) = &get_rounded_secs_and_millis($time);
	
	my @localtime = localtime($secs);
	my $formatted_time = strftime("%H:%M:%S", @localtime);
	
	return "$formatted_time.$millis";
}

# Format a timestamp to full localtime string, including milliseconds
sub format_datetime {
	my ($time) = @_;
	
	my ($secs, $millis) = &get_rounded_secs_and_millis($time);
	
	my @localtime = localtime($secs);
	my $date_time = strftime("%a %b %e %H:%M:%S", @localtime);
	my $year = strftime("%Y", @localtime);
	
	return "$date_time.$millis $year";
}

# Round a number of seconds to the nearest millisecond
sub round_to_millis {
	my ($time) = @_;
	
	my ($secs, $millis) = &get_rounded_secs_and_millis($time);

	return "$secs.$millis";
}

# Given a floating point number of seconds, return an
# array containing the number of seconds and the number of
# milliseconds, rounded to the nearest millisecond using
# half-up rounding.
# We need this because sprintf() uses banker's rounding,
# which leads to inconsistent times in the logs.
sub get_rounded_secs_and_millis {
	my ($time) = @_;
	
	my $secs = int($time);
	my $millis = &round(($time - $secs) * 1000);

	if ($millis == 1000) {
		$secs += 1;
		$millis = 0;
	}
	
	return ($secs, sprintf("%03d", $millis));
}

# Format a number of seconds to: XXX days, HH:mm:ss
sub format_duration {
	my ($duration) = @_;
	
	my $days = int($duration / 86400);
	my $hours = int(($duration % 86400) / 3600);
	my $mins = int(($duration % 86400 % 3600) / 60);
	my $secs = $duration % 86400 % 3600 % 60;
	
	return sprintf("%d days, %02d:%02d:%02d", $days, $hours, $mins, $secs);
	
}

# Returns the script uptime in the following format:
# XXX days, HH:mm:ss
sub script_uptime {
	return &format_duration(gettimeofday() - $script_start_time);
}

# Returns the total number of seconds spent in either the loaded
# or idle adaptive ICMP modes
sub get_icmp_adaptive_total_time {
	my ($mode) = @_;
	
	if (&is_icmp_adaptive_idle()) {
		if ($mode eq "loaded") {
			return $icmp_adaptive_loaded_total_time;
		} elsif ($mode eq "idle") {
			return $icmp_adaptive_idle_total_time + (gettimeofday() - $icmp_adaptive_idle_start_time);
		}
	} else {
		if ($mode eq "loaded") {
			return $icmp_adaptive_loaded_total_time + (gettimeofday() - $icmp_adaptive_loaded_start_time);
		} elsif ($mode eq "idle") {
			return $icmp_adaptive_idle_total_time;
		}
	}
}

# Get the number of bytes transferred on the WAN interface
# Returns an array containing the following:
# 1. The time stamp at which the data was read
# 2. A reference to a hashmap containing bytes counts from the WAN interface
#    for keys "upload" and "download"
#
# TODO: is there a better way to get the bandwidth that doesn't involve reading a device/file?
sub get_wan_bytes {
	if (open(DEVSTATS, '<', "/proc/net/dev")) {
		my $time = gettimeofday();
		my @devstats_array = <DEVSTATS>;
		
		chomp(@devstats_array);
		close(DEVSTATS);

		foreach my $devstats_line (@devstats_array) {
			if ($devstats_line =~ /^(\s*)?$wan_interface: /) {
				my @devstats_line_array = split(' ', $devstats_line);
				my %wan_bytes;
				$wan_bytes{"download"} = $devstats_line_array[1];
				$wan_bytes{"upload"} = $devstats_line_array[9];
	
				return ($time, \%wan_bytes);
			}
		}
		
		# If we reach here we couldn't read the contents of /proc/net/dev properly
		&output(0, "ERROR: Failed to get WAN bytes!")
	} else {
		# If we reach here we couldn't even open /proc/net/dev
		&output(0, "ERROR: Failed to open /proc/net/dev WAN bytes!");
	}
	
	# If we reach here something went badly wrong. Return an empty array to indicate an error.
	return ();
}

# Calculate kilobits/s from bytes and seconds
sub get_kbps {
	my ($bytes, $seconds) = @_;

	return sprintf("%.3f", ($bytes * 0.008) / $seconds);
}

# Convert kilobits per second to megabits per second
sub kbps_to_mbps {
	my ($kbps) = @_;

	return sprintf("%.3f", $kbps / 1000);
}

# Record the bandwidth usage since the last time this subroutine was called
sub update_bandwidth_usage_stats {
	# Get the current time and WAN bytes stats
	my ($current_time, $current_wan_bytes_ref) = &get_wan_bytes();
	my %current_wan_bytes = %{$current_wan_bytes_ref};
	my $wan_bytes_ul = $current_wan_bytes{"upload"};
	my $wan_bytes_dl = $current_wan_bytes{"download"};

	my @bandwidth_usage;
	if (scalar(@recent_bandwidth_usages) == 0) {
		# Initalise the @recent_bandwidth_usages array with a dummy entry
		# that contains enough information to calculate the bandwidth usage
		# between now and the next time this subroutine is called.
		@bandwidth_usage = (undef, $current_time, undef, undef, $wan_bytes_ul, $wan_bytes_dl);
	} else {
		# Get the most recent WAN bytes stats from the first element in @recent_bandwidth_usages
		my (undef, $previous_end_time, undef, undef, $previous_wan_bytes_ul, $previous_wan_bytes_dl) = @{$recent_bandwidth_usages[0]};

		# Calculate the bandwidth usage since the previous sample and store it
		# Bandwidth usage samples are ordered from newest -> oldest
		# so we only need to store the start time of each period
		my $bw_usage_ul = &get_kbps($wan_bytes_ul - $previous_wan_bytes_ul, $current_time - $previous_end_time);
		my $bw_usage_dl = &get_kbps($wan_bytes_dl - $previous_wan_bytes_dl, $current_time - $previous_end_time);
		@bandwidth_usage = ($previous_end_time, $current_time, $bw_usage_ul, $bw_usage_dl, $wan_bytes_ul, $wan_bytes_dl);
	}
	
	# Add the new bandwidth usage sample to the beginning of @recent_bandwidth_usages
	unshift(@recent_bandwidth_usages, \@bandwidth_usage);
	
	# If we have too many samples now, remove the oldest sample from the end of @recent_bandwidth_usages
	if (scalar(@recent_bandwidth_usages) > $max_recent_bandwidth_usages) {
		pop(@recent_bandwidth_usages);
	}
}

# Get the average bandwidth usage (kilobits/s) for the specified direction, for the
# period that contains the specified time.
sub get_bandwidth_usage_at {
	my ($time, $direction) = @_;
	
	my $start_time;
	my $bw_usage_ul;
	my $bw_usage_dl;
	
	# Bandwidth usage samples are ordered from newest -> oldest
	# so we only need to check the start time of each period
	foreach my $bw_usage_ref (@recent_bandwidth_usages) {
		($start_time, undef, $bw_usage_ul, $bw_usage_dl, undef, undef) = @{$bw_usage_ref};
		if ($time > $start_time) {
			if ($direction eq "upload") {
				return $bw_usage_ul;
			} else {
				return $bw_usage_dl;
			}
		}
	}
	
	# We didn't find a matching bandwidth usage sample
	# This should never happen. If it does we have a problem with how we're calculating $max_recent_bandwidth_usages.
	my ($earliest_start_time, undef, undef, undef) = @{$recent_bandwidth_usages[scalar(@recent_bandwidth_usages) - 1]};
	&fatal_error("Failed to get $direction bandwidth at ". &format_time($time) . ". Earliest of " . scalar(@recent_bandwidth_usages) . " (max $max_recent_bandwidth_usages) bandwidth samples' start time = " . &format_time($earliest_start_time));
}

# Check whether the connection has been idle in both directions for at least
# $icmp_adaptive_idle_delay seconds.
# Returns 1 if idle, 0 if loaded.
sub is_connection_idle {
	my $start_time;
	my $end_time;
	my $bw_usage_ul;
	my $bw_usage_dl;
		
	# Calculate the lower limit on times we need to search
	# If Adaptive ICMP is already in idle mode we only need to check the most
	# recent sample - we know all samples as far back as $icmp_adaptive_idle_delay
	# won't show any load.
	my $min_time = gettimeofday() - (&is_icmp_adaptive_idle() ? $latency_check_interval : $icmp_adaptive_idle_delay);
	
	# Bandwidth usage samples are ordered from newest -> oldest
	# We want to search backwards until we hit a sample whose
	# end time is greater than $min_time	
	foreach my $bw_usage_ref (@recent_bandwidth_usages) {
		($start_time, $end_time, $bw_usage_ul, $bw_usage_dl, undef, undef) = @{$bw_usage_ref};
		
		if (defined($start_time)) {  # Ensures this is a valid sample, not the first "dummy" sample
			if ($end_time > $min_time) {
				if ($bw_usage_ul >= $ul_bw_idle_threshold || $bw_usage_dl >= $dl_bw_idle_threshold) {
					# This sample indicates a loaded connection
					return 0;
				}
			} else {
				# If we reach here we've searched back as far as $icmp_adaptive_idle_delay
				# and found no samples that indicate a loaded connection
				return 1;
			}
		}
	}
	
	# If we reach here we ran out of samples before we could determine whether the
	# connection has been idle for $icmp_adaptive_idle_delay
	return 0;
}

# Get the average bandwidth usage (kilobits/s) for both directions since the last latency summary
sub get_average_bandwidth_usage_since_last_latency_summary {
	my $start_time;
	my $bw_usage_ul;
	my $bw_usage_dl;
	
	my $bw_usage_ul_total = 0;
	my $bw_usage_dl_total = 0;	
	my $current_time = gettimeofday();

	foreach my $bw_usage_ref (@recent_bandwidth_usages) {
		($start_time, undef, $bw_usage_ul, $bw_usage_dl, undef, undef) = @{$bw_usage_ref};
		if (defined($bw_usage_ul) && defined($bw_usage_dl)) {
			if ($start_time > $current_time - $latency_check_summary_interval) {
				$bw_usage_ul_total += $bw_usage_ul;
				$bw_usage_dl_total += $bw_usage_dl;
			} else {
				last;
			}
		}
	}
	
	return ($bw_usage_ul_total / scalar(@recent_bandwidth_usages), $bw_usage_dl_total / scalar(@recent_bandwidth_usages));
}

# Check whether Adaptive ICMP is currently in idle mode
# Return 1 if idling, otherwise return 0.
sub is_icmp_adaptive_idle {
	if ($icmp_adaptive_idle_suspend) {
		if (&are_icmp_threads_suspended()) {
			return 1;
		}
	} elsif ($icmp_interval == $icmp_interval_idle) {
		return 1;
	}
	
	return 0;
}

# Set Adaptive ICMP to idle mode	
sub set_icmp_adaptive_idle {
	if ($icmp_adaptive_idle_suspend) {
		if ($debug_icmp_adaptive) { &output(0, "ICMP ADAPTIVE DEBUG: Connection is idle - suspending ICMP threads"); }
		&suspend_icmp_threads();
		&clear_latency_results();
	} else {
		lock ($icmp_interval);
		$icmp_interval = $icmp_interval_idle;
		&update_reflector_strike_ttl();
		if ($debug_icmp_adaptive) { &output(0, "ICMP ADAPTIVE DEBUG: Connection is idle - ICMP interval set to $icmp_interval_idle" . "s, reflector strike TTL set to " . $reflector_strike_ttl . "s"); }
	}
	&update_auto_summary_intervals();
	
	$icmp_adaptive_idle_start_time = gettimeofday();
	$icmp_adaptive_loaded_total_time += $icmp_adaptive_idle_start_time - $icmp_adaptive_loaded_start_time;
}

# Set Adaptive ICMP to loaded mode
sub set_icmp_adaptive_loaded {
	if ($icmp_adaptive_idle_suspend) {
		if ($debug_icmp_adaptive) { &output(0, "ICMP ADAPTIVE DEBUG: Connection is loaded - resuming ICMP threads"); }
		&resume_icmp_threads();
	} else {
		lock ($icmp_interval);
		$icmp_interval = $icmp_interval_loaded;
		&update_reflector_strike_ttl();
		if ($debug_icmp_adaptive) { &output(0, "ICMP ADAPTIVE DEBUG: Connection is loaded - ICMP interval set to $icmp_interval_idle" . "s, reflector strike TTL set to " . $reflector_strike_ttl . "s"); }
	}
	&update_auto_summary_intervals();
	
	$icmp_adaptive_loaded_start_time = gettimeofday();
	$icmp_adaptive_idle_total_time += $icmp_adaptive_loaded_start_time - $icmp_adaptive_idle_start_time;
}

# Check whether the script has been active long enough to filter out
# any obviously bad reflectors from the initial set
sub is_icmp_warmup_done {
	if ($icmp_warmup_done) {
		# Warmup has already completed
		return 1;
	}
	
	if (!$icmp_adaptive) {
		# Adaptive ICMP is disabed. No need to warm up.
		$icmp_warmup_done = 1;
		return 1;
	}
	
	if ($reflector_strikeout_threshold == 0) {
		# Strikes are disabled - mark warmup as done and return
		$icmp_warmup_done = 1;
		return 1;
	}
	
	if ($reflectors_reloaded_ever) {
		# We've exhausted the reflector pool and reloaded it.
		# Extending the warmup period won't provide any benefit now.
		if ($debug_icmp_adaptive) { &output(0, "ICMP ADAPTIVE DEBUG: WARMUP: Warmup stopped due to exhaustion of reflector pool"); }
		$icmp_warmup_done = 1;
		return 1;		
	}
	
	# Check whether we've sent a request to all of the reflectors at least
	# enough times for obviously bad reflectors in the initial set to be
	# struckout and replaced
	my $warmup_request_threshold = $number_of_reflectors * ($reflector_strikeout_threshold + 1);
	if ($icmp_request_count < $warmup_request_threshold) {
		my $icmp_requests_remaining = $warmup_request_threshold - $icmp_request_count;
		if ($debug_icmp_adaptive) { &output(0, "ICMP ADAPTIVE DEBUG: WARMUP: $icmp_requests_remaining of $warmup_request_threshold ICMP requests remaining"); }
		return 0;
	}
		
	# Go through all the reflectors and check for strikes
	lock(%reflector_ips);
	my $strike_count = 0;
	foreach my $ip (keys(%reflector_ips)) {
		if ($debug_icmp_adaptive) {
			# Update the strike count and carry on
			$strike_count += &get_strike_count($ip, "upload") + &get_strike_count($ip, "download");
		} elsif (&get_strike_count($ip, "upload") || &get_strike_count($ip, "download")) {
			# Fast (none debug) path. Found a reflector strike => keep warming up
			return 0;
		}
	}
	
	if ($debug_icmp_adaptive && $strike_count > 0) {
		# Found at least one reflector strike. Print debug and keep warming up.
		&output(0, "ICMP ADAPTIVE DEBUG: WARMUP: Active strikes remaining: $strike_count");
		return 0;
	}
	
	# If we reach here there were no strikes against any reflectors
	if ($debug_icmp_adaptive) {
		my $warmup_duration = int(gettimeofday() - $script_start_time);
		my $hours = int(($warmup_duration % 86400) / 3600);
		my $mins = int(($warmup_duration % 86400 % 3600) / 60);
		my $secs = $warmup_duration % 86400 % 3600 % 60;
		&output(0, "ICMP ADAPTIVE DEBUG: WARMUP: No active strikes => warmup completed in " . sprintf("%02d:%02d:%02d", $hours, $mins, $secs));
	}
	$icmp_warmup_done = 1;
	return 1;
}

# Get the reflector pool from the specified CSV file.
# The reflector IP is expected to be in the first cell on each row.
# A simple list of IP addresses (one per line) is also accepted.
# The order of the reflectors is randomized before being returned.
sub get_reflector_pool {
	my ($csv_file) = @_;

	open(CSV, '<', $csv_file) || die ("Failed to open $csv_file");
	chomp(my @csv_file_array = <CSV>);
	close(CSV);

	# Read the reflector IPs into a hash. This ensures there are no dupes.
	my %reflector_pool;
	foreach my $csv_line (@csv_file_array) {
		my @csv_line_array = split(/,/, $csv_line);
		if ($csv_line_array[0] =~ /^(\d+\.\d+\.\d+\.\d+)$/) {
			$reflector_pool{$1} = 1;
		}
	}

	# Randomize the array of reflector IPs and return it
	return shuffle(keys(%reflector_pool));
}

# Get the specified number of reflectors from the pool
sub get_reflectors {
	my ($number_of_reflectors) = @_;

	# Sanity check
	if ($number_of_reflectors > scalar(@reflector_pool)) {
		&fatal_error("Requested $number_of_reflectors reflectors, but pool only contains " . scalar(@reflector_pool) . "!", 1);
	}

	my %reflectors;
	for (my $i = 0; $i < $number_of_reflectors; $i++) {
		# Take the next reflector from the pool and add it to our list
		my $reflector_ip = &get_reflector();
		$reflectors{$reflector_ip} = gettimeofday();
	}

	return %reflectors;
}

# Get the next non-duplicate reflector from the pool
sub get_reflector {
	my $reflector;
	
	my $reflectors_reloaded_here = 0;
	
	while(1) {
		if (scalar(@reflector_pool) > 0) {
			# Take the next reflector out of the pool
			$reflector = shift(@reflector_pool);
		} elsif (!$reflectors_reloaded_here) {
			# We ran out of reflectors. Re-read the pool from the CSV
			# and take the first reflector from it.
			&output(1, "WARNING: Reflector pool exhausted - reloading pool from CSV file", 1);
			@reflector_pool = &get_reflector_pool($reflectors_csv_file);
			$reflector = shift(@reflector_pool);
			$reflectors_reloaded_ever = 1;
			$reflectors_reloaded_here = 1;
			
			# Print current set of reflectors with seq numbers - this is useful
			# for identifying the most reliable reflectors
			&output(0, "INIT: Reflector list at pool reload:");
			{
				lock(%reflector_ips);
				
				# Sort reflectors by how long they've been active
				my @sorted_reflector_ips = sort {$reflector_ips{$a} <=> $reflector_ips{$b}} keys(%reflector_ips);
				foreach my $reflector_ip (@sorted_reflector_ips) {
					&output(0, "INIT:\t" . sprintf("%-15s since %s", $reflector_ip, &format_datetime($reflector_ips{$reflector_ip})));
				}
			}
		} else {
			&fatal_error("Failed to get unique reflector from reflector pool", 1);
		}
	
		# Make sure the new reflector isn't already in our list. If it is,
		# continue in the loop and get a new one.
		{
			lock(%reflector_ips);
			if (!exists($reflector_ips{$reflector})) {
				return $reflector;
			}
		}
	}
}

# Replace the specified reflector with a new reflector from the pool
sub replace_reflector {
	my ($reflector_ip) = @_;

	# Remove all the information associated with this reflector
	{
		lock(%reflector_ips);
		lock(%reflector_packet_ids);
		lock(%reflector_seqs);
		lock(%reflector_offsets);
		lock(%reflector_minimum_rtts);
		delete($reflector_ips{$reflector_ip});
		delete($reflector_packet_ids{$reflector_ip});
		delete($reflector_seqs{$reflector_ip});
		delete($reflector_offsets{$reflector_ip});
		delete($reflector_minimum_rtts{$reflector_ip});
	}
	&clear_strikes($reflector_ip, "upload");
	&clear_strikes($reflector_ip, "download");

	# Get a new reflector from the pool
	my $new_reflector_ip = &get_reflector();

	{
		lock(%reflector_ips);
		$reflector_ips{$new_reflector_ip} = gettimeofday();
	}

	return $new_reflector_ip;
}

# Record a strike against the specified reflector for the specified direction
sub record_strike {
	my ($ip, $packet_id, $seq, $time, $direction) = @_;
	
	if ($reflector_strikeout_threshold == 0) {
		# Strikes are disabled.
		return;
	}
	
	my @strikes = &get_strikes($ip, $direction);

	if (grep(/$packet_id-$seq/, @strikes)) {
		# We already know about this strike, so just return
		return;
	}
		
	# Add the strike to the start of the array
	unshift(@strikes, "$packet_id-$seq-$time");
			
	&set_strikes($ip, $direction, @strikes);

	if ($debug_strike) {
		&output(0, "STRIKE DEBUG: record_strike ($ip $packet_id-$seq-$time $direction): " . &get_strike_count($ip, $direction) . " / $reflector_strikeout_threshold. Strike list ($direction): " . join(" ", &get_strikes($ip, $direction)));
	}		
}

# Gets the number of strikes against the specified reflector for the specified direction
sub get_strike_count {
	my ($ip, $direction) = @_;
	
	my @strikes = &get_strikes($ip, $direction);

	return scalar(@strikes);
}

# Get the strikes for the specified reflector in the specified direction
sub get_strikes {
	my ($ip, $direction) = @_;
	
	if ($reflector_strikeout_threshold == 0) {
		# Strikes are disabled
		return ();
	}
	
	&check_direction($direction);

	my @strikes = ();
	if ($direction eq "upload") {
		if (exists($reflector_strikes_ul{$ip})) {
			@strikes = @{$reflector_strikes_ul{$ip}};
		}
	} else {
		if (exists($reflector_strikes_dl{$ip})) {
			@strikes = @{$reflector_strikes_dl{$ip}};
		}
	}
	
	if ($debug_strike) { &output(0, "STRIKE DEBUG: get_strikes ($ip $direction) before cleaning: " . join(" ", @strikes)); }
	
	# Go through the strikes array and remove strikes that have timed out
	if (scalar(@strikes) != 0) {
		my $current_time = gettimeofday();
		for (my $i = 0; $i < scalar(@strikes); $i++) {
			if ($strikes[$i] =~ /^\d+-\d+-(.+)$/) {
				my $expiry_time = $1;
				if ($expiry_time < $current_time) {
					# This strike has expired, which means all the remaining strikes have expired too
					my @expired_strikes = splice(@strikes, $i);
					if ($debug_strike) { &output(0, "STRIKE DEBUG: get_strikes ($ip $direction) expired strikes: " . join(" ", @expired_strikes)); }
					&set_strikes($ip, $direction, @strikes);
					last;
				}
			}
		}
	}
	
	if ($debug_strike) { &output(0, "STRIKE DEBUG: get_strikes ($ip $direction)  after cleaning: " . join(" ", @strikes)); }

	return @strikes;
}

# Set the strikes against the specified reflector for the specified direction
sub set_strikes {
	my ($ip, $direction, @strikes) = @_;
	
	if ($reflector_strikeout_threshold == 0) {
		# Strikes are disabled
		return;
	}
	
	&check_direction($direction);

	if ($direction eq "upload") {
		$reflector_strikes_ul{$ip} = \@strikes;
	} else {
		$reflector_strikes_dl{$ip} = \@strikes;
	}

	if ($debug_strike) { &output(0, "STRIKE DEBUG: set_strikes ($ip $direction): " . join(" ", @strikes)); }
}

# Clear strikes against the specified reflector for the specified direction
sub clear_strikes {
	my ($ip, $direction) = @_;
	
	if ($reflector_strikeout_threshold == 0) {
		# Strikes are disabled
		return;
	}
	
	&check_direction($direction);

	if ($direction eq "upload") {
		if (exists($reflector_strikes_ul{$ip})) {
			delete($reflector_strikes_ul{$ip});
			if ($debug_strike) { &output(0, "STRIKE DEBUG: clear_strikes ($ip $direction)"); }
		}
	} else {
		if (exists($reflector_strikes_dl{$ip})) {
			delete($reflector_strikes_dl{$ip});
			if ($debug_strike) { &output(0, "STRIKE DEBUG: clear_strikes ($ip $direction)"); }
        }
	}
}

# Clear all strikes against all reflectors
sub clear_all_strikes {
	%reflector_strikes_ul = ();
	%reflector_strikes_dl = ();
	if ($debug_strike) { &output(0, "STRIKE DEBUG: clear_all_strikes"); }
}

# If reflector strike TTL is set to "auto", update it based on the current ICMP interval
sub update_reflector_strike_ttl {
	if (&get_config_property("reflector_strike_ttl", "auto") eq "auto") {
		$reflector_strike_ttl = &round(($number_of_reflectors / (1 / $icmp_interval)) * ($reflector_strikeout_threshold + 1));
	}
}

# Check whether a reflector has reached $reflector_strikeout_threshold
# for the specified direction.
# Returns 1 if it has, 0 if it hasn't.
sub is_struckout {
	my ($ip, $direction) = @_;
	
	if ($reflector_strikeout_threshold != 0 && &get_strike_count($ip, $direction) >= $reflector_strikeout_threshold) {
		if ($debug_strike) { &output(0, "STRIKE DEBUG: is_struckout ($ip $direction): yes"); }
		return 1;
	} else {
		if ($debug_strike) { &output(0, "STRIKE DEBUG: is_struckout ($ip $direction): no"); }
		return 0;
	}
}

# Returns the current bandwidth for the specified direction (download|upload)
# The value returned here is the value maintained by this script.
# Use &get_current_bandwidth_from_tc() to refresh the value from tc.
sub get_current_bandwidth {
	my ($direction) = @_;
	
	&check_direction($direction);
	
	if ($direction eq "upload") {
		return $current_bandwidth_ul;
	} else {
		return $current_bandwidth_dl;
	}	
}

# Returns the current bandwidth for the specified direction (download|upload)
# from the SQM config. We should only need to do this once during initialisation.
sub get_current_bandwidth_from_tc {
	my ($direction) = @_;

	&check_direction($direction);
 
	my $interface = "";
	if ($direction eq "download") {
		$interface = $dl_interfaces[0];
	}
	if ($direction eq "upload") {
		$interface = $ul_interfaces[0];
	}
	
	my @qdiscs = split(/\n/, &run_sys_command("tc -d qdisc"));
	foreach my $qdisc (@qdiscs) {
                if ($qdisc =~ / dev $interface .* bandwidth /) {
                        if ($qdisc =~ / dev $interface .* bandwidth (\d+)(G|K|M)bit/) {
                                my $bw = $1;
                                my $bw_units = $2;
                                if ($bw_units eq "K") {
                                        return $bw;
                                } elsif ($bw_units eq "M") {
                                        return $bw * 1000;
                                } elsif ($bw_units eq "G") {
                                        return $bw * 1000000;
                                }
                        } else {
                                &fatal_error("Failed to get bandwidth from tc output for interface \"$interface\":\n$qdisc");
                        }
                }
        }

        # If we reach here the first interface for the specified direction wasn't listed in the tc output
        &fatal_error("Failed to get bandwidth from tc output for interface \"$interface\"");
}

# Get the maximum allowed latency for the specified direction when bandwidth usage is significant
sub get_max_loaded_latency {
	my ($direction) = @_;

	&check_direction($direction);

	if ($direction eq "upload") {
		return $ul_max_loaded_latency;
	} else {
		return $dl_max_loaded_latency;
	}
}

# Set the average latency observed for "good" ICMP results in the most recent latency check
sub set_average_good_latency {
	my ($direction, $average_ping) = @_;

	&check_direction($direction);

	if ($direction eq "upload") {
		$average_good_latency_ul = $average_ping;
	} else {
		$average_good_latency_dl = $average_ping;
	}
}

# Get the average latency observed for "good" ICMP results in the most recent latency check
sub get_average_good_latency {
	my ($direction) = @_;

	&check_direction($direction);

	if ($direction eq "upload") {
		return $average_good_latency_ul;
	} else {
		return $average_good_latency_dl;
	}
}

# Set the average bandwidth usage observed across all results during the most recent latency check
sub set_average_bandwidth_usage {
	my ($direction, $average_bw_usage) = @_;
	
	&check_direction($direction);
	
	if ($direction eq "upload") {
		$average_bandwidth_usage_ul = $average_bw_usage;
	} else {
		$average_bandwidth_usage_dl = $average_bw_usage;
	}
}

# Get the average bandwidth usage observed across all results during the most recent latency check
sub get_average_bandwidth_usage {
	my ($direction) = @_;

	&check_direction($direction);

	if ($direction eq "upload") {
		return $average_bandwidth_usage_ul;
	} else {
		return $average_bandwidth_usage_dl;
	}
}

# Set the average bandwidth usage observed for "bad" ICMP results during the most recent latency check
sub set_average_bad_bandwidth_usage {
	my ($direction, $average_bw_usage) = @_;

	&check_direction($direction);

	if ($direction eq "upload") {
		$average_bad_bandwidth_usage_ul = $average_bw_usage;
	} else {
		$average_bad_bandwidth_usage_dl = $average_bw_usage;
	}
}

# Get the average bandwidth usage observed for "bad" ICMP results during the most recent latency check
sub get_average_bad_bandwidth_usage {
	my ($direction) = @_;

	&check_direction($direction);

	if ($direction eq "upload") {
		return $average_bad_bandwidth_usage_ul;
	} else {
		return $average_bad_bandwidth_usage_dl;
	}
}

# Get the current bandwidth increase percentage step based on the most recent latency check results
sub get_increase_step_pc {
	my ($direction) = @_;

	&check_direction($direction);

	if ($direction eq "upload") {
		return $increase_step_pc_ul;
	} else {
		return $increase_step_pc_dl;
	}
}

# Set the current bandwidth increase percentage step based on the most recent latency check results
sub set_increase_step_pc {
	my ($direction, $new_step_pc) = @_;

	&check_direction($direction);

	if ($direction eq "upload") {
		$increase_step_pc_ul = sprintf("%.2f", $new_step_pc);
	} else {
		$increase_step_pc_dl = sprintf("%.2f", $new_step_pc);
	}
}

# Get the current bandwidth decrease percentage step based on the most recent latency check results
sub get_decrease_step_pc {
	my ($direction) = @_;

	&check_direction($direction);

	if ($direction eq "upload") {
		return $decrease_step_pc_ul;
	} else {
		return $decrease_step_pc_dl;
	}
}

# Set the current bandwidth decrease percentage step based on the most recent latency check results
sub set_decrease_step_pc {
	my ($direction, $new_step_pc) = @_;

	&check_direction($direction);

	if ($direction eq "upload") {
		$decrease_step_pc_ul = sprintf("%.2f", $new_step_pc);
	} else {
		$decrease_step_pc_dl = sprintf("%.2f", $new_step_pc);
	}
}

# Returns the standard bandwidth for the specified direction (download|upload), in Kilobits/s
sub get_std_bandwidth {
	my ($direction) = @_;

	&check_direction($direction);

	if ($direction eq "upload") {
		return $ul_bw_standard;
	} else {
		return $dl_bw_standard;
	}
}

# Returns the minimum bandwidth for the specified direction (download|upload), in Kilobits/s
sub get_min_bandwidth {
	my ($direction) = @_;

	&check_direction($direction);

	if ($direction eq "upload") {
		return $ul_bw_minimum;
	} else {
		return $dl_bw_minimum;
	}
}

# Returns the minimum bandwidth for the specified direction (download|upload) in Kilobits/s
sub get_max_bandwidth {
	my ($direction) = @_;

	&check_direction($direction);

	if ($direction eq "upload") {
		return $ul_bw_maximum;
	} else {
		return $dl_bw_maximum;
	}
}

# Return 1 if the current bandwidth is set to the standard rate for the specified
# direction, otherwise return 0
sub is_bandwidth_at_std {
	my ($direction) = @_;

	if (&get_current_bandwidth($direction) == &get_std_bandwidth($direction)) {
		return 1;
	} else {
		return 0;
	}
}

# Return 1 if the current bandwidth is set to the minimum for the specified
# direction, otherwise return 0
sub is_bandwidth_at_min {
	my ($direction, $log_if_at_min) = @_;

	if (&get_current_bandwidth($direction) == &get_min_bandwidth($direction)) {
		if ($log_if_at_min) {
			&output(0, ucfirst($direction) . " bandwidth is set to minimum.");
		}
		return 1;
	} else {
		return 0;
	}
}

# Return 1 if the current bandwidth is set to the maximum for the specified
# direction, otherwise return 0
sub is_bandwidth_at_max {
	my ($direction) = @_;

	if (&get_current_bandwidth($direction) == &get_max_bandwidth($direction)) {
		return 1;
	} else {
		return 0;
	}
}

# Check whether the current bandwidths are within the min/max range, and if
# not, fix them. This can happen if the min/max settings are modified outside
# of this script.
sub ensure_within_min_max {
	my @directions = ("download", "upload");
	foreach my $direction (@directions) {
		my $current = &get_current_bandwidth($direction);
		my $min = &get_min_bandwidth($direction);
		my $max = &get_max_bandwidth($direction);

		if ($current > $max) {
			&output(1, "Current $direction bandwidth ($current Kb/s) is greater than the maximum ($max Kb/s) => setting to maximum.");
			if (&set_bandwidth($direction, $max)) {
				&set_last_change($direction, "reset");
			}
		}

		if ($current < $min) {
			&output(1, "Current $direction bandwidth ($current Kb/s) is less than the minimum ($min Kb/s) => setting to minimum.");
			if (&set_bandwidth($direction, $min)) {
				&set_last_change($direction, "reset");
			}
		}
	}
}

# Relax the bandwidth limit towards the standard bandwidth if appropriate
# Returns 1 if the relax step went ahead, and 0 if not.
sub relax_if_appropriate {
	my ($direction, $summary_results_array_ref, $detailed_results_array_ref) = @_;

	# Don't proceed if we're already at the standard bandwidth
	if (&get_current_bandwidth($direction) == &get_std_bandwidth($direction)) {
		return 0;
	}

	# Don't relax if load is greater than $relax_load_threshold_pc
	if (&get_average_bandwidth_usage($direction) / &get_current_bandwidth($direction) > ($relax_load_threshold_pc / 100)) {
		return 0;
	}
	
	if (!&is_relax_allowed($direction, 0)) {
		return 0;
	}

	# If we reach here, everything looks good to proceed with the relax step

	# Print detailed and summary latency results
	if ($log_bw_changes || $log_details_on_bw_changes) { &print_log_line_separator_if_necessary(); }
	if ($log_details_on_bw_changes || $debug_latency_check) { &print_latency_results_details(@{$detailed_results_array_ref}); }
	if ($log_bw_changes) { &print_latency_results_summary(@{$summary_results_array_ref}); }

	return &relax_bandwidth($direction);
}

# Increase the bandwidth unless we are already maxed out, or increases
# are disallowed (i.e. after a recent bandwidth change)
# Returns 1 if bandwidth was increased, 0 if not.
sub increase_if_appropriate {
	my ($direction, $summary_results_array_ref, $detailed_results_array_ref) = @_;

	# Check whether we are maxed out
	if (&is_bandwidth_at_max($direction)) {
		return 0;
	}

	# Check whether an increase is allowed
	if (!&is_increase_allowed($direction, 0)) {
		return 0;
	}

	# Check whether we had sufficient bandwidth usage
	if (&get_average_bandwidth_usage($direction) / &get_current_bandwidth($direction) < ($increase_load_threshold_pc / 100)) {
		return 0;
	}

	# Print detailed and summary latency results
	if ($log_bw_changes || $log_details_on_bw_changes) { &print_log_line_separator_if_necessary(); }
	if ($log_details_on_bw_changes || $debug_latency_check) { &print_latency_results_details(@{$detailed_results_array_ref}); }
	if ($log_bw_changes) { &print_latency_results_summary(@{$summary_results_array_ref}); }

	return &increase_bandwidth($direction);
}

# Decrease the bandwidth for the specified direction, unless it's already at the minimum.
# Returns 1 if bandwidth was decreased, 0 if not.
sub decrease_if_appropriate {
	my ($direction, $summary_results_array_ref, $detailed_results_array_ref) = @_;

	# Always print detailed and summary latency results when a decrease is requested
	if ($log_bw_changes || $log_details_on_bw_changes) { &print_log_line_separator_if_necessary(); }
	if ($log_details_on_bw_changes || $debug_latency_check) { &print_latency_results_details(@{$detailed_results_array_ref}); }
	if ($log_bw_changes) { &print_latency_results_summary(@{$summary_results_array_ref}); }

	if (&is_bandwidth_at_min($direction, 0)) {
		&output(1, "WARNING: " . ucfirst($direction) . " bandwidth decrease of " . &get_decrease_step_pc($direction) . "% requested, but already at minimum");
		return 0;
	}

	return &decrease_bandwidth($direction);
}

# Check whether a relaxation is allowed for the specified direction
# Returns 1 if relaxation is allowed, 0 if not
sub is_relax_allowed {
	my ($direction, $log_if_disallowed) = @_;

	my ($seconds_until_allowed, $delay) = &get_time_until_relax_allowed($direction);
	my $time_at_which_allowed = &format_time(gettimeofday() + $seconds_until_allowed);
	
	if ($seconds_until_allowed > 0) {
		if ($log_if_disallowed) {		
			&output(0,
				sprintf("%s relaxations disallowed until %s (%.3f/%ds remaining)",
					ucfirst($direction),
					$time_at_which_allowed,
					&round_to_millis($seconds_until_allowed),
					$delay
				)
			);
		}
		return 0;
	}

	# If the current bandwidth is lower than the standard bandwidth, the relax step
	# will be an increase, so we need to check whether a bandwidth increase is allowed.
	# Note that this is not the same check as above. We perform this check regardless
	# of whether the last change was an increase or a decrease, and the conditions
	# in &is_increase_allowed() are more stringent, requiring a full set of clean ping
	# results in addition to respecting increase delay settings.
	if (&get_current_bandwidth($direction) < &get_std_bandwidth($direction) && !is_increase_allowed($direction, 0)) {
		return 0;
	}

	# Don't relax if we haven't had at least a full set of pings since the last bandwidth
	# change. This ensures that our decision is based on an average bandwidth usage over
	# at least $max_recent_results samples.
	# If the ICMP threads are suspended it means adaptive ICMP is enabled and the
	# connection is idle, so we're not going to have any recent results => skip this check.
	if (!&are_icmp_threads_suspended()) {
		my $results_count;
		{
			lock(@recent_results);
			$results_count = scalar(@recent_results);
		}
		if ($results_count < $max_recent_results) {
			return 0;
		}
	}

	# No reason to disallow a relaxation step
	return 1;
}

# Return 1 if a bandwidth increase for the specified direction is allowed. Return 0
# if increasing the bandwidth is disallowed.
# The current time is provided by the caller to ensure that times printed in the
# log are consistent
sub is_increase_allowed {
	my ($direction, $log_if_disallowed) = @_;

	my ($seconds_until_allowed, $delay) = &get_time_until_increase_allowed($direction);
	my $time_at_which_allowed = &format_time(gettimeofday() + $seconds_until_allowed);

	my $results_count;
	{
		lock(@recent_results);
		$results_count = scalar(@recent_results);
	}

	if ($seconds_until_allowed > 0) {
		if ($log_if_disallowed) {		
			&output(0,
				sprintf("%s increase disallowed until %s (%.3f/%ds remaining)",
					ucfirst($direction),
					$time_at_which_allowed,
					&round_to_millis($seconds_until_allowed),
					$delay
				)
			);
		}
		return 0;
	} elsif (!&are_icmp_threads_suspended()) {
		# If the ICMP threads are suspended it means adaptive ICMP is enabled and the
		# connection is idle, so we don't need to perform these checks
		if ($results_count < $max_recent_results) {
			# We haven't seen enough good pings yet
			return 0;
		} elsif (&get_increase_step_pc($direction) == 0) {
			# Increase step is set to 0, which means not all recent pings were good.
			return 0;
		}
	}

	# If we reach here there's no reason to prevent an increase
	return 1;
}

# Returns an array containing:
#   - The number of seconds (millisecond precision) until a bandwidth
#     relaxation is allowed for the specified direction
#   - The length of the delay that we are respecting (could be increase
#     delay for the specified direction, or $relax_delay)
sub get_time_until_relax_allowed {
	my ($direction) = @_;

	my $last_change_type = &get_last_change_type($direction);
	my $time_since_last_change = &time_since_last_change($direction);

	# A relaxation might be disallowed by the increase delay for the
	# specified direction, or $relax_delay.
	# We need to respect the increase delay because if we don't we
	# might increase too soon if a relaxation step happens and a
	# surge in load triggers an increase shortly afterwards.
	# We don't know which delay is larger, so we need to get both
	# and compare them.

	# Get the remaining time to comply with $relax_delay
	my $time_until_relax_delay_expires = $relax_delay - $time_since_last_change;

	# Get the remaining time to comply with the increase delay for
	# the specified direction.
	my $delay;
	my $time_until_increase_delay_expires;
	if ($last_change_type eq "decrease") {
		$time_until_increase_delay_expires = $increase_delay_after_decrease - $time_since_last_change;
		$delay = $increase_delay_after_decrease;
	} elsif ($last_change_type eq "increase") {
		$time_until_increase_delay_expires = $increase_delay_after_increase - $time_since_last_change;
		$delay = $increase_delay_after_increase;
	} else {
		# The last change was not an increase or a decrease
		# (i.e. it was a relax or a reset) so no increase delay
		# applies.
		$time_until_increase_delay_expires = 0;
	}
	
	# Compare $relax_delay and the increase delay and select the largest
	my $time_until_delay_expires;
	if ($time_until_increase_delay_expires > $time_until_relax_delay_expires) {
		# We're respecting the increase delay
		$time_until_delay_expires = $time_until_increase_delay_expires; 
	} else {
		# We're respecting $relax_delay
		$time_until_delay_expires = $time_until_relax_delay_expires;
		$delay = $relax_delay;
	}
	
	if ($time_until_delay_expires > 0) {
		return ($time_until_delay_expires, $delay);
	} else {
		# Time is negative, set to 0
		return (0, 0);
	}
}

# Returns the number of seconds until we will be allowed to increase the bandwidth
# for the specified direction
# Returns an array containing:
#   - The number of seconds until a bandwidth increase is allowed for the specified direction
#   - The length of the delay that we are respecting (could be $increase_delay_after_decrease
#     or $increase_delay_after_increase)
sub get_time_until_increase_allowed {
	my ($direction) = @_;

	my $delay = 0;
	if (&get_last_change_type($direction) eq "decrease") {
		$delay = $increase_delay_after_decrease;
	}
	if (&get_last_change_type($direction) eq "increase") {	
		$delay = $increase_delay_after_increase;
	}
	
	my $result = $delay - &time_since_last_change($direction);

	if ($result > 0) {
		return ($result, $delay);
	} else {
		return (0, $delay);
	}	
}

# Adjust the bandwidth by $relax_pc towards the standard bandwidth
# Returns 1 if bandwidth was relaxed successfully, 0 if not.
sub relax_bandwidth {
	my ($direction) = @_;

	my $need_to_resume_icmp_threads = 0;
	if (!&are_icmp_threads_suspended()) {
		&suspend_icmp_threads();
		$need_to_resume_icmp_threads = 1;
	}

	my $std_bw = &get_std_bandwidth($direction);
	my $current_bw = &get_current_bandwidth($direction);
	my $new_bw;

	if ($current_bw > $std_bw) {
		# New bandwidth is current bandwidth minus $relax_pc, or $std_bw (whichever is higher)
		$new_bw = &round($current_bw - ($current_bw * ($relax_pc/100)));
		if ($new_bw < $std_bw) {
			$new_bw = $std_bw;
		}
	} else {
		# New bandwidth is current bandwidth plus $relax_pc, or $std_bw (whichever is lower)
		$new_bw = &round($current_bw + ($current_bw * ($relax_pc/100)));
		if ($new_bw > $std_bw) {
			$new_bw = $std_bw;
		}
	}

	# Send a message to the log to explain what we're doing
	if ($log_bw_changes) {
		my $output_string = "";

		if ($new_bw == $std_bw) {
			$output_string .= "Relaxing $direction bandwidth to $new_bw Kb/s (standard) ";
		} else {
			$output_string .= "Relaxing $direction bandwidth by " . $relax_pc . "% to $new_bw Kb/s ";
		}
		
		my $average_load = &get_average_bandwidth_usage($direction);

		$output_string .= sprintf(
			"(average load %.3fMbps (%.2f%%), %.3fs since last change)",
			&kbps_to_mbps($average_load),
			($average_load / $current_bw) * 100,
			&round_to_millis(&time_since_last_change($direction))
		);
	
		&output(1, $output_string, 0);
	}
	
	# Finally, set the bandwidth
	if (&set_bandwidth($direction, $new_bw)) {
		&set_last_change($direction, "relax");
		
		if ($log_bw_changes) {
			# If the new bandwidth is not equal to the standard, describe the new relaxation delay
			if ($new_bw != $std_bw && $relax_delay > 0) {
				my ($seconds_until_allowed, $delay) = &get_time_until_relax_allowed($direction);
				my $time_at_which_allowed = &format_time(gettimeofday() + $seconds_until_allowed);
				output(1, "Relaxations disallowed until $time_at_which_allowed (" . $delay . "s)");
			}
		}
		
		if ($need_to_resume_icmp_threads) {
			&resume_icmp_threads();
		}
		return 1;
	} else {
		if ($need_to_resume_icmp_threads) {
			&resume_icmp_threads();
		}
		return 0;
	}
}

# Increase the bandwidth for the specified direction, ensuring that we
# respect the maximum limit.
# Returns 1 if bandwidth was increased successfully, 0 if not.
sub increase_bandwidth {
	my ($direction) = @_;
	
	my $need_to_resume_icmp_threads = 0;
	if (!&are_icmp_threads_suspended()) {
		&suspend_icmp_threads();
		$need_to_resume_icmp_threads = 1;
	}

	my $output_string .= "Increasing $direction bandwidth ";

	# Get the increase step and sanity check it
	my $increase_pc = &get_increase_step_pc($direction);
	if ($increase_pc <= 0) {
		&output(1, "WARNING: Invalid increase percentage step: " . $increase_pc . "%", 1);
		if ($need_to_resume_icmp_threads) {
			&resume_icmp_threads();
		}
		return 0;
	}

	# Calculate the new bandwidth in kilobits/s
	my $current_bandwidth = &get_current_bandwidth($direction);
	my $max_bandwidth = &get_max_bandwidth($direction);
	my $new_bandwidth = &round($current_bandwidth + ($current_bandwidth * ($increase_pc/100)));

	if ($new_bandwidth >= $max_bandwidth) {
		$new_bandwidth = $max_bandwidth;
		$output_string .= "to $new_bandwidth Kb/s (maximum) ";
	} else {
		$output_string .= "by $increase_pc" . "% to $new_bandwidth Kb/s ";
	}

	my $average_load = &get_average_bandwidth_usage($direction);
	
	# Send information to the log describing what we're going to do..
	if ($log_bw_changes) {
		$output_string .= sprintf(
			"(average latency %.2fms, average load %.3fMbps (%.2f%%))",
			&get_average_good_latency($direction),
			&kbps_to_mbps($average_load),
			($average_load / $current_bandwidth) * 100
		);
		&output(1, $output_string, 0);
	}

	# Now actually set the bandwidth
	if (&set_bandwidth($direction, $new_bandwidth)) {
		&set_last_change($direction, "increase");
		
		if ($log_bw_changes) {
			# If the new bandwidth is not equal to the maximum, describe the new increase delay
			if ($new_bandwidth != &get_max_bandwidth($direction) && $increase_delay_after_increase > 0) {
				my ($seconds_until_allowed, $delay) = &get_time_until_increase_allowed($direction);
				my $time_at_which_allowed = &format_time(gettimeofday() + $seconds_until_allowed);
				&output(1, "Increases disallowed until $time_at_which_allowed (" . $delay . "s)");
			}
			
			# If the new bandwidth is not equal to the standard, describe the new relaxation delay
			if ($new_bandwidth != &get_std_bandwidth($direction) && $relax_delay > 0) {
				my ($seconds_until_allowed, $delay) = &get_time_until_relax_allowed($direction);
				my $time_at_which_allowed = &format_time(gettimeofday() + $seconds_until_allowed);
				&output(1, "Relaxations disallowed until $time_at_which_allowed (" . $delay . "s)");
			}
		}
		
		if ($need_to_resume_icmp_threads) {
			&resume_icmp_threads();
		}
		return 1;
	} else {
		if ($need_to_resume_icmp_threads) {
			&resume_icmp_threads();
		}
		return 0;
	}
}

# Decrease the bandwidth for the specified direction, ensuring that we
# respect the minimum limit.
# Returns 1 if bandwidth was decreased successfully, 0 if not.
sub decrease_bandwidth {
	my ($direction) = @_;

	my $need_to_resume_icmp_threads = 0;
	if (!&are_icmp_threads_suspended()) {
		&suspend_icmp_threads();
		$need_to_resume_icmp_threads = 1;
	}

	my $output_string .= "Decreasing $direction bandwidth ";

	# Get the decrease step and sanity check it
	my $decrease_pc = &get_decrease_step_pc($direction);
	if ($decrease_pc <= 0) {
		&output(1, "WARNING: Invalid decrease percentage step: " . $decrease_pc . "%", 1);
		if ($need_to_resume_icmp_threads) {
			&resume_icmp_threads();
		}
		return 0;
	}

	# Calculate the new bandwidth (in kilobits/s)
	my $current_bandwidth = &get_current_bandwidth($direction);
	my $min_bandwidth = &get_min_bandwidth($direction);
	my $new_bandwidth = &round($current_bandwidth - ($current_bandwidth * ($decrease_pc/100)));

	my $is_high_priority_log = 0;
	if ($new_bandwidth <= $min_bandwidth) {
		$new_bandwidth = $min_bandwidth;
		$is_high_priority_log = 1;
		$output_string .= "to $new_bandwidth Kb/s (minimum) ";
	} else {
		$output_string .= "by $decrease_pc" . "% to $new_bandwidth Kb/s ";
	}

	if ($log_bw_changes) {
		$output_string .= sprintf(
			"(average bad bandwidth usage %.2fMbps)",
			&kbps_to_mbps(&get_average_bad_bandwidth_usage($direction))
		);
	
		# Send information to the log describing the decrease
		&output(1, $output_string, $is_high_priority_log);
	}

	# Now actually set the bandwidth
	if (&set_bandwidth($direction, $new_bandwidth)) {
		&set_last_change($direction, "decrease");
		
		if ($log_bw_changes) {
			# Describe the new increase delay
			my ($seconds_until_allowed, $delay) = &get_time_until_increase_allowed($direction);
			my $time_at_which_allowed = &format_time(gettimeofday() + $seconds_until_allowed);
			&output(1, "Increases disallowed until $time_at_which_allowed (" . $delay . "s)");
			
			# If the bandwidth is not equal to the standard, describe the new relaxation delay
			if ($new_bandwidth != &get_std_bandwidth($direction) && $relax_delay > 0) {
				($seconds_until_allowed, $delay) = &get_time_until_relax_allowed($direction);
				$time_at_which_allowed = &format_time(gettimeofday() + $seconds_until_allowed);
				&output(1, "Relaxations disallowed until $time_at_which_allowed (" . $delay . "s)");
			}
		}
		
		if ($need_to_resume_icmp_threads) {
			&resume_icmp_threads();
		}
		return 1;
	} else {
		if ($need_to_resume_icmp_threads) {
			&resume_icmp_threads();
		}
		return 0;
	}
}

# Reset upload and/or download bandwidths to the standard (relaxed) values
sub reset_bandwidth {
	my ($direction) = @_;
	
	if (defined($direction)) {
		&check_direction($direction);
	}

	my $need_to_resume_icmp_threads = 0;
	if (!&are_icmp_threads_suspended()) {
		&suspend_icmp_threads();
		$need_to_resume_icmp_threads = 1;
	}

	my $std_bandwidth_dl = &get_std_bandwidth("download");
	my $std_bandwidth_ul = &get_std_bandwidth("upload");

	if ($log_bw_changes) {
		if (!defined($direction)) {
			&output(1, "Resetting bandwidth to standard rates: $std_bandwidth_dl Kb/s download, $std_bandwidth_ul Kb/s upload.");
		} elsif ($direction eq "download") {
			&output(1, "Resetting download bandwidth to standard rate: $std_bandwidth_dl Kb/s.");
		} elsif ($direction eq "upload") {
			&output(1, "Resetting download bandwidth to standard rate: $std_bandwidth_ul Kb/s.");
		}
	}

	if (!defined($direction) || $direction eq "download") {
		if (&set_bandwidth("download", $std_bandwidth_dl)) {
			&set_last_change("download", "reset");
		}
	}

	if (!defined($direction) || $direction eq "upload") {
		if (&set_bandwidth("upload", $std_bandwidth_ul)) {
			&set_last_change("upload", "reset");
		}
	}
	
	if ($need_to_resume_icmp_threads) {
		&resume_icmp_threads();
	}
}

# Apply the specified bandwidth to the specified direction (download|upload).
# Returns 1 if bandwidth was applied successfully, 0 otherwise.
# Note: the bandwidth must be an integer value in kilobits/s
sub set_bandwidth {
	my ($direction, $new_bandwidth) = @_;

	&check_direction($direction);

	# Sanity check that the specified bandwidth makes sense.
	# Specifying a bad value can disable SQM or even cut off access to the internet or the router!
	$new_bandwidth = &round($new_bandwidth);  # convert to integer (otherwise tc will barf)
	if (
		$new_bandwidth eq "" ||
		$new_bandwidth !~ /^\d+$/ ||
		$new_bandwidth > &get_max_bandwidth($direction) ||
		$new_bandwidth < &get_min_bandwidth($direction)
	) {
		&output(1, "WARNING: bad $direction bandwidth value specified ($new_bandwidth Kb/s). Not setting bandwidth.", 1);
		return 0;
	}

	# If the new bandwidth is the same as the current bandwidth we don't actually need to do anything
	if ($new_bandwidth == &get_current_bandwidth($direction)) {
		&output(0, "WARNING: Specified $direction bandwidth ($new_bandwidth Kb/s) already in use.");
		return 0;
	}

	if ($dryrun) {
		# Don't set the bandwidth, but pretend we did
		&output(0, "WARNING: Dry run, so not setting $direction bandwidth.");

		# Clear the latency results so we start from scratch after a bandwidth change
		&clear_latency_results();

		return 1;
	} else {
		my $errors = "";

		if ($direction eq "upload") {
			foreach my $interface (@ul_interfaces) {
				$errors .= &set_bandwidth_for_interface($interface, $new_bandwidth);
			}
		}

		if ($direction eq "download") {
			foreach my $interface (@dl_interfaces) {
				$errors .= &set_bandwidth_for_interface($interface, $new_bandwidth);
			}
		}

		if ($errors eq "") { 
			if ($debug_bw_changes) { &output(0, "New $direction bandwidth applied successfully"); }
			
			# Update the cached current bandwidth value for the specified direction
			if ($direction eq "upload") {
				$current_bandwidth_ul = $new_bandwidth;
			} else {
				$current_bandwidth_dl = $new_bandwidth;
			}
			
			# Clear the latency results so we start from scratch after a bandwidth change
			&clear_latency_results();
			
			return 1;
		} else {
			&output(1, "WARNING: Problem(s) setting $direction bandwidth: $errors", 1);
			return 0;
		}
	}

	# Should not reach here.
}

# Set the SQM bandwidth for the specified interface and direction (ingress|egress)
# Returns any errors, or an empty string if successful
# Note: the bandwidth must be an integer value in kilobits/s
sub set_bandwidth_for_interface {
	my ($interface, $bandwidth) = @_;

	my $errors = "";

	# Use tc to change the bandwidth on the fly, without restarting SQM.
	# The tc command should complete silently.
	my $tc_command = "tc qdisc change root dev $interface cake bandwidth " . $bandwidth . "Kbit";
	if ($debug_bw_changes) { &output(0, "Applying new bandwidth $bandwidth Kb/s to $interface: $tc_command"); }
	$errors .= &run_sys_command($tc_command);
	chomp($errors);

	# Check whether we had any errors.
	if ($errors ne "") {
		if ($debug_bw_changes) { &output(0, $errors) };
	}

	return $errors;
}
