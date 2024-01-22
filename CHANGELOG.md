# Changelog

## [1.7 - 18.01.2024]
### Added
- Configuration parameter to add automatic ioc

## [1.6 - 21.12.2023]
### Added
- Added support for Service User
- Added documentation for Service User
- Added documentation for required permissions in the role for Normal user or Service user

### Changed
- Automatic add note and update verdict for case sample was marked as Clean by VMRay

## [1.5 - 25.07.2023]
### Added
- Confidence filter feature for threats
- Deep visibility maximum count variable
- Configurable false positive marking feature for clean samples
- Pagination to endpoints that have a limit

### Changed
- get_sites function limit
- Default evidence download method

## [1.4 - 05.06.2023]
### Added
- Configuration parameter to resubmit a known file based on the verdict
- Configuration parameter to download evidence file from cloud

### Changed
- Default values in README.md updated with conf.py

## [1.3 - 16.02.2023]
### Added
- Configuration parameter to unlock automatic report

## [1.2 - 19.09.2022]
### Added
- Configuration parameter to filter sample collection methods
- Configuration parameter to filter IOC fields in threat notes
- Configuration parameter to filter analysis results in threat notes

### Changed
- IOCs title added to threat note
- URL field added to IOCs
- Sample collection from processes (deep visibility) is disabled by default

### Fixed
- Key conflict error for evidence and process found in VMRay
- VTI sort error in threat notes
- IOC sort error in threat notes
- Domain and IP resolution with URL

## [1.1 - Initial Release] - 10.06.2022
