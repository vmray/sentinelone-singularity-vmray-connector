# VMRay Analyzer Connector for SentinelOne

**Latest Version:** 1.0 - **Release Date:** June 07, 2022

<p align="center">
  <img src="app/imgs/vmray.png" alt="drawing" width="430"/>
</p>
<p align="center">
  <img src="app/imgs/sentinelone.png" alt="drawing" width="400"/>
</p>
    
## Overview

This project aims to integrate SentinelOne Singularity and VMRay Analyzer. The connector collects threats and processes files, and query or submit these samples into VMRay Analyzer. After the submission, it retrieves IOC values from VMRay Analyzer and adds them as a note in SentinelOne Threat Notes. It enriches SentinelOne Singularity with IOCs retrieved from reports of VMRay Analyzer. So it enables analysts to have much more contextual data regarding a file threat.

The connector also regularly checks for benign process files to enable Blind Spot Detection.

If configured, the connector can also run automated actions which are disabled by default like killing processes, quarantining files, adding evidence sha1 values to blacklist, disconnecting computers from network, shutting down computers and starting antivirus scans.

The connector works with both the Report and Verdict API key types for both onprem and cloud deployments of VMRay Analyzer.



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
- SentinelOne Signularity API Token
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

| Configuration Item            | Description                                                 | Default                                              |
|:------------------------------|:------------------------------------------------------------|:-----------------------------------------------------|
| `API_KEY_TYPE`                | Enum for VMRay API Key Type [`REPORT`/`VERDICT`]            | `REPORT`                                             |
| `URL`                         | URL of VMRay instance                                       | `https://eu.cloud.vmray.com`                         |
| `SSL_VERIFY`                  | Enable or disable certificate verification [`True`/`False`] | `True`                                               |
| `SUBMISSION_COMMENT`          | Comment for submitted samples                               | `Sample from VMRay Analyzer - SentinelOne Connector` |
| `SUBMISSION_TAGS`             | Tags for submitted samples                                  | `SentinelOne`                                        |
| `SEND_CUSTOM_SUBMISSION_TAGS` | Append custom tag for submitted samples                     | `False`                                              |
| `ANALYSIS_TIMEOUT`            | Timeout for submission analyses as seconds                  | `120`                                                |
| `ANALYSIS_JOB_TIMEOUT`        | Timeout for analysis job in wait_submissions as seconds     | `900`                                                |
| `CONNECTOR_NAME`              | Connector Name                                              | `SentinelOne`                                        |
| `CONNECTOR_VERSION`           | Connector Version                                           | `1.0`                                                |

## SentinelOne Configurations

- Generate an API Token with web interface. (`Settings > Users > Click your username > API Token Generate`)

- If the API Token expired, regenerate an API Token from within the web interface. (`Settings > Users > Click your username > Options > Regenerate API Token`)

Note: API Token expiration period is 6 months. [More details](https://usea1-partners.sentinelone.net/docs/en/generating-api-tokens.html)

- Edit the 'SentinelOneConfig' class in [conf.py](app/config/conf.py) file.

| Configuration Item                               | Description                                                              | Default                                      |
|:-------------------------------------------------|:-------------------------------------------------------------------------|:---------------------------------------------|
| `API` > `HOSTNAME_URL`                           | Hostname to access SentinelOne                                           |                                              |
| `API` > `API_PREFIX`                             | API Prefix to create SentinelOne API URL                                 | `web/api/v2.1`                               |
| `API` > `USER_AGENT`                             | User-Agent value to use for SentinelOne                                  | `S1-VMRayAnalyzer-Connector`                 |
| `API` > `MAX_DATA_COUNT`                         | Maximum data count that could be fetched in each request                 | `1000`                                       |
| `API` > `FETCH_FILE_TIMEOUT`                     | Timeout for fetching a sample file in seconds                            | `60`                                         |
| `API` > `FETCH_FILE_TIME_SPAN`                   | Time span for each fetched sample file in seconds                        | `10`                                         |
| `DOWNLOAD` > `DIR`                               | Directory name to store downloaded samples                               | `downloads`                                  |
| `PROCESS` > `FILTER_QUERY`                       | Filter Query to get processes                                            | `ObjectType = "Process"`                     |
| `INDICATOR` > `NAME`                             | Name for indicators which were created by connector                      | `Indicator based on VMRay Analyzer Report`   |
| `INDICATOR` > `DESCRIPTION`                      | Description for indicators which were created by connector               | `Indicator based on VMRay Analyzer Report`   |
| `INDICATOR` > `SOURCE`                           | Source for indicators which were created by connector                    | `Indicator based on VMRay Analyzer Report`   |
| `BLACKLIST` > `AUTO_ADD_GLOBAL` > `ACTIVE`       | Automated add to global blacklist with SHA1 hash values [`True`/`False`] | `False`                                      |
| `BLACKLIST` > `AUTO_ADD_GLOBAL` > `VERDICTS`     | Selected verdicts to add to global blacklist automatically               | [`suspicious`,`malicious`]                   |
| `BLACKLIST` > `AUTO_ADD_GLOBAL` > `DESCRIPTION`  | Description for added to global blacklist automatically                  | `Indicator based on VMRay Analyzer Report`   |
| `BLACKLIST` > `AUTO_ADD_THREAT` > `ACTIVE`       | Automated add to threat blacklist with SHA1 hash values [`True`/`False`] | `False`                                      |
| `BLACKLIST` > `AUTO_ADD_THEAT` > `VERDICTS`      | Selected verdicts to add to threat blacklist automatically               | [`suspicious`,`malicious`]                   |
| `BLACKLIST` > `AUTO_ADD_THREAT` > `DESCRIPTION`  | Description for added to threat blacklist automatically                  | `Indicator based on a VMRay Analyzer Report` |
| `BLACKLIST` > `AUTO_ADD_WITH_DV` > `ACTIVE`      | Automated add to blacklist with SHA1 hash values [`True`/`False`]        | `False`                                      |
| `BLACKLIST` > `AUTO_ADD_WITH_DV` > `VERDICTS`    | Selected verdicts to add to blacklist with deep visibility automatically | [`suspicious`,`malicious`]                   |
| `ACTION` > `AUTO_KILL` > `ACTIVE`                | Automated kill process status [`True`/`False`]                           | `False`                                      |
| `ACTION` > `AUTO_KILL` > `VERDICTS`              | Selected verdicts to kill process automatically                          | [`suspicious`,`malicious`]                   |
| `ACTION` > `AUTO_QUARANTINE` > `ACTIVE`          | Automated add quarantine status [`True`/`False`]                         | `False`                                      |
| `ACTION` > `AUTO_QUARANTINE` > `VERDICTS`        | Selected verdicts to add quarantine automatically                        | [`suspicious`,`malicious`]                   |
| `ACTION` > `AUTO_DISCONNECT` > `ACTIVE`          | Automated disconnect machine from network status [`True`/`False`]        | `False`                                      |
| `ACTION` > `AUTO_DISCONNECT` > `VERDICTS`        | Selected verdicts to disconnect machine from network automatically       | [`suspicious`,`malicious`]                   |
| `ACTION` > `AUTO_SHUTDOWN` > `ACTIVE`            | Automated shutdown machine status [`True`/`False`]                       | `False`                                      |
| `ACTION` > `AUTO_SHUTDOWN` > `VERDICTS`          | Selected verdicts to shutdown machine automatically                      | [`suspicious`,`malicious`]                   |
| `ACTION` > `AUTO_INITIATE_SCAN` > `ACTIVE`       | Automated anti virus scan status [`True`/`False`]                        | `False`                                      |
| `ACTION` > `AUTO_INITIATE_SCAN` > `VERDICTS`     | Selected verdicts to anti virus scan automatically                       | [`suspicious`,`malicious`]                   |
| `TIME_SPAN`                                      | Alert polling time span as seconds                                       | `3600`                                       |
| `ACCOUNT_ID`                                     | SentinelOne Account ID for filtering                                     | `[]`                                         |
| `SITE_IDS`                                       | SentinelOne Site IDs for filtering                                       | `[]`                                         |
| `ZIP_PASSWORD`                                   | ZIP Password to use for download files                                   | `SentinelEvidenceFile.!`                     |
| `SUBMISSION_CUSTOM_TAG_PROPERTY`                 | Custom tag property for VMRay submission                                 | `siteId`                                     |

## General Connector Configurations

- Edit environment variables in [.env](app/config/.env) file.

| Configuration Item              | Description           | Default                        |
|:--------------------------------|:----------------------|:-------------------------------|
| `API_KEY`                       | VMRay API Key         |                                |
| `API_TOKEN`                     | SentinelOne API Token |                                |


- Edit the `GeneralConfig` class in [conf.py](app/config/conf.py) file.

| Configuration Item  | Description                                    | Default                  |
|:--------------------|:-----------------------------------------------|:-------------------------|
| `LOG_FILE_PATH`     | Connector log file path                        | `sentinel-connector.log` |
| `LOG LEVEL`         | Logging verbosity level                        | `INFO`                   |
| `SELECTED_VERDICTS` | Selected verdicts to analyze                   | `suspicious,malicious`   |
| `TIME_SPAN`         | Time span between script iterations as seconds | `300`                    |
| `RUNTIME_MODE`      | Runtime mode for script                        | `DOCKER`                 |

## IOC Configurations

- Edit the `IOC_FIELD_MAPPINGS` in [conf.py](app/config/conf.py) file. You can enable or disable IOC types with comments.

| IOC Type | Description               | SentinelOne Field Names |
|:---------|:--------------------------|:------------------------|
| `ipv4`   | Connected IPV4 address    | `IPV4`                  |
| `sha256` | SHA256 Hash value of file | `SHA256`                |
| `domain` | Connected domain          | `DNS`                   |
| `sha1`   | SHA1 Hash value of file   | `SHA1`                  |
| `md5`    | MD5 Hash value of file    | `MD5`                   |
