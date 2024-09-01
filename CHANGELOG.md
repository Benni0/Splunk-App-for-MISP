# First App Release
This release includes the first version of the Splunk App - Benni0 App for MISP.
This App provides the following features:
- Splunk modular inputs for MISP events and attributes.
- Splunk custom search commands for MISP events `mispsearchevents` and attributes `mispsearchattributes`.
- Splunk alert action for adding sightings to MISP attributes `add_sighting`.
- Reports for lookuptable generation.
- Lookuptable `misp_decaying_scores.csv` for configuration of score decaying on Splunk side.
- Splunk Dashboards for IOC search and IOC statistics (lookuptables must be generated first).