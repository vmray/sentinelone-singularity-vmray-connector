# VMRay Analyzer Connector for SentinelOne

**Latest Version:** 1.7 - **Release Date:** January 18, 2024

<p align="center">
  <img src="app/imgs/vmray.png" alt="drawing" width="430"/>
</p>
<p align="center">
  <img src="app/imgs/sentinelone.png" alt="drawing" width="400"/>
</p>
    
## Overview

This project aims to integrate SentinelOne Singularity XDR and VMRay Analyzer to enrich incidents and provide intel on detected threats. The connector collects threats and processes files, and query or submit these samples into VMRay Analyzer. After the submission, and following detonation it retrieves back:

 - Threat Classification
 - VMRay Threat Identifiers (VTIs)
 - IOCs 

and adds them to the SentinelOne Threat Notes. It also enriches SentinelOne Singularity with IOCs retrieved from reports of VMRay Analyzer.

Being configured to submit not only threats but all processes started on the endpoints protected by SentinelOne, the connector allows you to build an extra line of defense and reliably detect even yet unknown threats.

If configured, the connector can also run automated actions which are disabled by default like killing processes, quarantining files, adding evidence sha1 values to blacklist, disconnecting computers from network, shutting down computers and starting antivirus scans.


## Related VMRay Products
The connector supports following VMRay products:
- Final Verdict
- Total Insight

## Project Structure

    app                             # Main project directory
    ├─── config                     # Configuration directory
    │   └─── __init__.py    
    │   └─── conf.py                # Connector configuration file
    ├─── imgs                       # Image directory for readme.md
    │   └─── sentinelone.png        # SentinelOne logo
    │   └─── vmray.png              # VMRay logo
    ├─── downloads                  # Directory for extracted binaries
    ├─── lib                        # Library directory
    │   └─── __init__.py     
    │   └─── SentinelOne.py         # SentineOne API functions
    │   └─── VMRay.py               # VMRay API functions
    ├─── log                        # Log directory for connector
        └─── sentinelone-connector.log      # Log file for connector
    └─── __init__.py
    └─── connector.py               # Main connector application
    └─── requirements.txt           # Python library requirements

## Requirements

- Python 3.x with required packages ([Required Packages](app/requirements.txt))
- SentinelOne Singularity API Token
- VMRay Analyzer API Key
- Docker (optional)

## Installation

Clone the repository into a local folder.

    git clone https://github.com/vmray/sentinelone-singularity-vmray-connector.git

Install the requirements.

    cd sentinelone-singularity-vmray-connector/app
    pip install -r requirements.txt

Update the [conf.py](app/config/conf.py) file with your specific configurations.

# Running the Connector

## Running with CLI (Recommended for Testing)

You can start the connector with command line after completing the configurations. You need to set `RUNTIME_MODE` as `RUNTIME_MODE.CLI` in the `GeneralConfig`. Also, you can create cron job for continuous processing.

    python connector.py

## Running with Docker (Recommended for Production)

You can create and start Docker image with Dockerfile after completing the configurations. You need to set `RUNTIME_MODE` as `RUNTIME_MODE.DOCKER` in the `GeneralConfig`.

    docker build -t s1_connector .
    docker run -d -v $(pwd)/log:/app/log -v $(pwd)/app/config:/app/config -t s1_connector

After running the Docker container you can see connector logs in the log directory on your host machine.

## VMRay Configurations

- Create an API Key from the web interface (`Analysis Settings > API Keys`). Remember that connector works with both the Report and Verdict API Key types. If the Verdict API Key is given, the connector will unlock the report if the sample's verdict is not clean.

- Edit the `VMRayConfig` class in [conf.py](app/config/conf.py) file.

| Configuration Item                   | Description                                                                             | Default                                               |
|:-------------------------------------|:----------------------------------------------------------------------------------------|:------------------------------------------------------|
| `API_KEY`                            | API Key                                                                                 |                                                       |
| `AUTO_UNLOCK_REPORT`                 | Unlock reports automatically for Verdict API                                            | `False`                                               |
| `URL`                                | URL of VMRay instance                                                                   | `https://eu.cloud.vmray.com`                          |
| `SSL_VERIFY`                         | Enable or disable certificate verification [`True`/`False`]                             | `True`                                                |
| `SUBMISSION_COMMENT`                 | Comment for submitted samples                                                           | `Sample from VMRay Analyzer - SentinelOne Connector`  |
| `SUBMISSION_TAGS`                    | Tags for submitted samples                                                              | [`SentinelOne`]                                       |
| `SEND_CUSTOM_SUBMISSION_TAGS`        | Append custom tag for submitted samples                                                 | `False`                                               |
| `ANALYSIS_TIMEOUT`                   | Timeout for submission analyses as seconds                                              | `120`                                                 |
| `ANALYSIS_JOB_TIMEOUT`               | Timeout for analysis job in wait_submissions as seconds                                 | `900`                                                 |
| `CONNECTOR_NAME`                     | Connector Name                                                                          | `SentinelOne`                                         |
| `CONNECTOR_VERSION`                  | Connector Version                                                                       | `1.4`                                                 |
| `RESUBMIT`                           | Resubmission flag for samples which has been already analyzed by VMRay [`True`/`False`] | `False`                                               |
| `RESUBMISSION_VERDICTS`              | Selected verdicts to resubmit evidences                                                 | [`suspicious`,`malicious`]                            |

## SentinelOne Configurations

- Option-1: Normal User
  - Generate an API Token with web interface. (`Settings > Users > Click your username > API Token Generate`)

  - If the API Token expired, regenerate an API Token from within the web interface. (`Settings > Users > Click your username > Options > Regenerate API Token`)

  Note: API Token expiration period is 6 months. [More details](https://usea1-partners.sentinelone.net/docs/en/generating-api-tokens.html)

- Option-2: Service User
  - Create Service User and generate an API Token with web interface (`Settings > Users > Service Users > Actions > Create New Service User`)

  - If the API Token expired, regenerate a Service User from within the web interface. (`Settings > Users > Service Users > Actions > Create New Service User`)

* Required permissions in the role for Normal user or Service user. (`Settings > Users > Roles > Click your role`)

| Category                                      | Permission Type             | Description                                                                                                                                                                   | 
|:----------------------------------------------|:----------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Endpoint                                      | View                        | Required by default                                                                                                                                                           |
| Endpoint                                      | View Threats                | Required by default                                                                                                                                                           |
| Endpoint                                      | Shut Down                   | Required if `ACTION` > `AUTO_SHUTDOWN` > `ACTIVE` configuration is Enabled                                                                                                    |
| Endpoint                                      | Search on Deep Visibility   | Required if `SELECTED_COLLECT_METHODS` > `deep-visibility` configuration is Enabled                                                                                           |
| Endpoint                                      | Initiate Scan               | Required if `ACTION` > `AUTO_INITIATE_SCAN` > `ACTIVE` configuration is Enabled                                                                                               |
| Endpoint                                      | File Fetch                  | Required if `SELECTED_COLLECT_METHODS` > `deep-visibility` configuration is Enabled                                                                                           |
| Endpoint                                      | Disconnect From Network     | Required if `ACTION` > `AUTO_DISCONNECT` > `ACTIVE` configuration is Enabled                                                                                                  |
| Endpoint Threats                              | View                        | Required by default                                                                                                                                                           |
| Endpoint Threats                              | Update Analyst Verdict      | Required if `THREAT` > `AUTO_UPDATE_FALSE_POSITIVE_VERDICT` > `ACTIVE` configuration is Enabled                                                                               |
| Endpoint Threats                              | Threat Actions > Quarantine | Required if `ACTION` > `AUTO_QUARANTINE` > `ACTIVE` configuration is Enabled                                                                                                  |
| Endpoint Threats                              | Threat Actions > Kill       | Required if `ACTION` > `AUTO_KILL` > `ACTIVE` configuration is Enabled                                                                                                        |
| Endpoint Threats                              | Fetch Threat File           | Required by default                                                                                                                                                           |
| Account                                       | View                        | Required by default                                                                                                                                                           |
| Activity                                      | View                        | Required by default                                                                                                                                                           |
| Blocklist                                     | View                        | Required if `BLACKLIST` > `AUTO_ADD_GLOBAL` > `ACTIVE`                                                                                                                        |
| Blocklist                                     | Create                      | Required if `BLACKLIST` > `AUTO_ADD_GLOBAL` > `ACTIVE`, `BLACKLIST` > `AUTO_ADD_THREAT` > `ACTIVE`, `BLACKLIST` > `AUTO_ADD_WITH_DV` > `ACTIVE` any  configuration is Enabled |
| SDL Search (Previously Skylight)              | View                        | Required if `SELECTED_COLLECT_METHODS` > `deep-visibility` configuration is Enabled                                                                                           |
| SDL Search (Previously Skylight)              | File Fetch                  | Required if `SELECTED_COLLECT_METHODS` > `deep-visibility` configuration is Enabled                                                                                           |
| SDL Search (Previously Skylight)              | Create                      | Required if `SELECTED_COLLECT_METHODS` > `deep-visibility` configuration is Enabled                                                                                           |
| Sites                                         | View                        | Required by default                                                                                                                                                           |
| Threat Intelligence                           | View                        | Required if `INDICATOR` > `ACTIVE` configuration is Enabled                                                                                                                   |
| Threat Intelligence                           | Manage                      | Required if `INDICATOR` > `ACTIVE` configuration is Enabled                                                                                                                   |

- Edit the 'SentinelOneConfig' class in [conf.py](app/config/conf.py) file.

| Configuration Item                                              | Description                                                                           | Default                                                     |
|:----------------------------------------------------------------|:--------------------------------------------------------------------------------------|:------------------------------------------------------------|
| `API` > `API_TOKEN`                                             | SentinelOne API Token                                                                 |                                                             |
| `API` > `HOSTNAME_URL`                                          | Hostname to access SentinelOne                                                        | `https://usea1-partners.sentinelone.net`                    |
| `API` > `API_PREFIX`                                            | API Prefix to create SentinelOne API URL                                              | `web/api/v2.1`                                              |
| `API` > `USER_AGENT`                                            | User-Agent value to use for SentinelOne                                               | `S1-VMRayAnalyzer-Connector`                                |
| `API` > `MAX_DATA_COUNT`                                        | Maximum data count that could be fetched in each request                              | `1000`                                                      |
| `API` > `MAX_DV_DATA_COUNT`                                     | Maximum deep visibility data count that could be fetched in each request              | `20000`                                                     |
| `API` > `FETCH_FILE_TIMEOUT`                                    | Timeout for fetching a sample file in seconds                                         | `60`                                                        |
| `API` > `FETCH_FILE_TIME_SPAN`                                  | Time span for each fetched sample file in seconds                                     | `10`                                                        |
| `DOWNLOAD` > `DIR`                                              | Directory name to store downloaded samples                                            | `downloads`                                                 |
| `DOWNLOAD` > `EVIDENCE_DOWNLOAD_METHOD`                         | Method to be used to download samples                                                 | `fetch-file`                                                |
| `PROCESS` > `FILTER_QUERY`                                      | Filter Query to get processes                                                         | `ObjectType = "Process"`                                    |
| `INDICATOR` > `ACTIVE`                                          | Automated add to indicators which were created by connector [`True`/`False`]          | `False`                                                     |
| `INDICATOR` > `NAME`                                            | Name for indicators which were created by connector                                   | `Indicator based on a VMRay Analyzer Report`                |
| `INDICATOR` > `DESCRIPTION`                                     | Description for indicators which were created by connector                            | `Indicator based on a VMRay Analyzer Report`                |
| `INDICATOR` > `SOURCE`                                          | Source for indicators which were created by connector                                 | `VMRay`                                                     |
| `BLACKLIST` > `AUTO_ADD_GLOBAL` > `ACTIVE`                      | Automated add to global blacklist with SHA1 hash values [`True`/`False`]              | `False`                                                     |
| `BLACKLIST` > `AUTO_ADD_GLOBAL` > `VERDICTS`                    | Selected verdicts to add to global blacklist automatically                            | [`malicious`]                                               |
| `BLACKLIST` > `AUTO_ADD_GLOBAL` > `DESCRIPTION`                 | Description for added to global blacklist automatically                               | `Reported from VMRay Analyzer`                              |
| `BLACKLIST` > `AUTO_ADD_THREAT` > `ACTIVE`                      | Automated add to threat blacklist with SHA1 hash values [`True`/`False`]              | `False`                                                     |
| `BLACKLIST` > `AUTO_ADD_THEAT` > `VERDICTS`                     | Selected verdicts to add to threat blacklist automatically                            | [`malicious`]                                               |
| `BLACKLIST` > `AUTO_ADD_THREAT` > `DESCRIPTION`                 | Description for added to threat blacklist automatically                               | `Reported from VMRay Analyzer`                              |
| `BLACKLIST` > `AUTO_ADD_WITH_DV` > `ACTIVE`                     | Automated add to blacklist with SHA1 hash values [`True`/`False`]                     | `False`                                                     |
| `BLACKLIST` > `AUTO_ADD_WITH_DV` > `VERDICTS`                   | Selected verdicts to add to blacklist with deep visibility automatically              | [`malicious`]                                               |
| `ACTION` > `AUTO_KILL` > `ACTIVE`                               | Automated kill process status [`True`/`False`]                                        | `False`                                                     |
| `ACTION` > `AUTO_KILL` > `VERDICTS`                             | Selected verdicts to kill process automatically                                       | [`malicious`]                                               |
| `ACTION` > `AUTO_QUARANTINE` > `ACTIVE`                         | Automated add quarantine status [`True`/`False`]                                      | `False`                                                     |
| `ACTION` > `AUTO_QUARANTINE` > `VERDICTS`                       | Selected verdicts to add quarantine automatically                                     | [`malicious`]                                               |
| `ACTION` > `AUTO_DISCONNECT` > `ACTIVE`                         | Automated disconnect machine from network status [`True`/`False`]                     | `False`                                                     |
| `ACTION` > `AUTO_DISCONNECT` > `VERDICTS`                       | Selected verdicts to disconnect machine from network automatically                    | [`malicious`]                                               |
| `ACTION` > `AUTO_SHUTDOWN` > `ACTIVE`                           | Automated shutdown machine status [`True`/`False`]                                    | `False`                                                     |
| `ACTION` > `AUTO_SHUTDOWN` > `VERDICTS`                         | Selected verdicts to shutdown machine automatically                                   | [`malicious`]                                               |
| `ACTION` > `AUTO_INITIATE_SCAN` > `ACTIVE`                      | Automated anti virus scan status [`True`/`False`]                                     | `False`                                                     |
| `ACTION` > `AUTO_INITIATE_SCAN` > `VERDICTS`                    | Selected verdicts to anti virus scan automatically                                    | [`malicious`]                                               |
| `NOTE` > `SELECTED_SUBTYPES`                                    | Selected subtypes to add to threat note                                               | [`verdict`,`vti`,`ioc`]                                     |
| `NOTE` > `SELECTED_IOC_FIELDS`                                  | Selected ioc fields to add to threat note                                             | [`md5`,`sha1`,`sha256`,`ipv4`,`domain`,`url`]               |
| `THREAT` > `AUTO_UPDATE_FALSE_POSITIVE_VERDICT` > `ACTIVE`      | Automatic analyst verdict update as false positive for clean samples [`True`/`False`] | `False`                                                     |
| `THREAT` > `AUTO_UPDATE_FALSE_POSITIVE_VERDICT` > `VERDICTS`    | Selected verdicts to be marked as false positive automatically                        | [`malicious`, `suspicious`]                                 |
| `THREAT` > `AUTO_UPDATE_FALSE_POSITIVE_VERDICT` > `DESCRIPTION` | Threat note description to be marked as false positive automatically                  | `Marked as False Positive because marked as clean by VMRay` |
| `TIME_SPAN`                                                     | Alert polling time span as seconds                                                    | `3600`                                                      |
| `ACCOUNT_ID`                                                    | SentinelOne Account ID for filtering                                                  | `""`                                                        |
| `SITE_IDS`                                                      | SentinelOne Site IDs for filtering                                                    | `[]`                                                        |
| `SUBMISSION_CUSTOM_TAG_PROPERTY`                                | Custom tag property for VMRay submission                                              | `siteName`                                                  |
| `SELECTED_COLLECT_METHODS`                                      | Methods to be used to collect samples                                                 | [`threat`]                                                  |
| `SELECTED_CONFIDENCE_LEVELS`                                    | Methods to be used to filter threat files by confidence levels                        | [`malicious`, `suspicious`, `n/a`]                          |

**Note:** To download threat files from Cloud, you must have a site with Singularity™ Complete SKU. [More details](https://usea1-partners.sentinelone.net/docs/en/binary-vault.html)

## General Connector Configurations

- Edit the `GeneralConfig` class in [conf.py](app/config/conf.py) file.

| Configuration Item  | Description                                    | Default                  |
|:--------------------|:-----------------------------------------------|:-------------------------|
| `LOG_FILE_PATH`     | Connector log file path                        | `sentinel-connector.log` |
| `LOG LEVEL`         | Logging verbosity level                        | `INFO`                   |
| `SELECTED_VERDICTS` | Selected verdicts to analyze                   | [`malicious`]            |
| `TIME_SPAN`         | Time span between script iterations as seconds | `300`                    |
| `RUNTIME_MODE`      | Runtime mode for script                        | `DOCKER`                 |

## IOC Configurations

- Edit the `IOC_FIELD_MAPPINGS` in [conf.py](app/config/conf.py) file. You can enable or disable IOC types with comments.

| IOC Type | Description               | SentinelOne Field Names |
|:---------|:--------------------------|:------------------------|
| `ipv4`   | Connected IPV4 address    | `IPV4`                  |
| `sha256` | SHA256 Hash value of file | `SHA256`                |
| `domain` | Connected domain          | `DNS`                   |
| `url`    | Connected url             | `URL`                   |
| `sha1`   | SHA1 Hash value of file   | `SHA1`                  |
| `md5`    | MD5 Hash value of file    | `MD5`                   |
