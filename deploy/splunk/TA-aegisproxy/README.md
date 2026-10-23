# AegisProxy Add-on for Splunk

1. Create an HEC token (index of your choice) and add a **Splunk HTTP Event Collector** destination in
   AegisProxy (Settings → Integrations → Log export) with format **json** and source type prefix `aegisproxy`.
2. Install this add-on on search heads (and indexers/heavy forwarders when HEC is terminated there):
   `tar czf TA-aegisproxy.tgz TA-aegisproxy` and upload it, or copy the directory to `$SPLUNK_HOME/etc/apps/`.
3. Events are mapped to the CIM data models **Web** (`aegisproxy:traffic`), **Change** (`aegisproxy:audit`) and
   **Intrusion Detection** (`aegisproxy:security`), so Splunk Enterprise Security correlation searches and
   dashboards work without custom searches.

Example: `tag=web tag=proxy action=blocked | stats count by src_host, dest`.
