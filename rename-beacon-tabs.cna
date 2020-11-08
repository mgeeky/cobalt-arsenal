#
# Beacons tabs renaming script.
#
# Lets us rename tabs from a default format of: 
#   Beacon <ip>@<pid>
#
# to anything other we like. Take note that the script only renames Beacon-related
# tabs, leaving SSH ones untouched. The renaming action kicks in every 15 seconds, as registered
# in heartbeat_15s event handler. 
#
# Format deciding how should each Beacon's tab be named, utilising beacon's metadata fields
# is described in a global variable named $beacon_tab_name_format . That variable may contain
# any of the following available beacon's metadata keys (CobaltStrike 4.2):
#   note, charset, internal , alive, session, listener, pid, lastf, computer, host, 
#   is64, id, process, ver, last, os, barch, phint, external, port, build, pbid, arch, 
#   user, _accent
#
# Example:
#   $beacon_tab_name_format = "B: <user>@<computer> (<pid>)";
#
# Author:
#   Mariusz B. / mgeeky, '20
#   <mb [at] binary-offensive.com>
#   (https://github.com/mgeeky)
#

$beacon_tab_name_format = "B: <user>@<computer> (<pid>)";


on heartbeat_15s {
    if($beacon_tab_name_format is $null || strlen($beacon_tab_name_format) == 0) {
        return;
    }

    renameBeaconTabs();
}

sub renameBeaconTabs {
    local('$bid');

    foreach $bid (beacon_ids()) {
        renameBeaconTab($bid);
    }
}

sub renameBeaconTab {
    local('$client $srctabname $i $dsttabname $apptabs $applicationTab');

    if($beacon_tab_name_format is $null || strlen($beacon_tab_name_format) == 0) {
        return;
    }

    $bid = $1;
    $client = getAggressorClient();
    $apptabs = [[$client tabs] apptabs];

    $srctabname = "Beacon " . beacon_info($bid, 'host') . "@" . beacon_info($bid, 'pid');
    $srctabname = [$srctabname trim];
    
    for ( $i = 0; $i < [$apptabs size] ; $i++) {
        $applicationTab = [$apptabs get: $i];

        if ([$applicationTab bid] eq $bid) {
            $currtabname = [[[$applicationTab label] getText] trim];

            if ($currtabname eq $srctabname) {
                $dsttabname = $beacon_tab_name_format;

                foreach $beacon (beacons()) {
                    if ($beacon['id'] eq $bid) {
                        foreach $k => $v ($beacon) {
                            $dsttabname = replace($dsttabname, '<' . $k . '>', $v);
                        }
                    }
                }

                # For some reason when we call setField to set title property of
                # applicationTab var, the beacon tab's title gets reverted to its previous
                # value, completely ignoring followed setText(). No clue what's going on, so we
                # better avoid the setField call.
                #setField($applicationTab, title => $dsttabname);
                [[$applicationTab label] setText: $dsttabname . "   "];
            } 
        }
    }
}

renameBeaconTabs();