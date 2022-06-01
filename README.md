# SentinelOne for VMRay Analyzer 

**Latest Version:** 1.0 - **Release Date:** 06/01/2022

## Overview

This project is an integration between SentinelOne and VMRay Analyzer. The connector will collect threats and processes files, and query or submit these samples into VMRay Sandbox. After the submission, it retrieves IOC values from VMRay and add note in SentinelOne Threat. It enriches threats with metadata information retrieved from VMRay Analyzer. If configured, the connector also can run automated actions like killing process, quarantining file, adding evidence sha1 value to blacklist, disconnecting computer from network, shutting down computer and starting antivirus scan.

## Project Structure

    app                             # Main project directory
    ├─── config                     # Configuration directory
    │   └─── __init__.py 			
    │   └─── conf.py                # Connector configuration file
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
- SentinelOne
- VMRay Analyzer
- Docker (optional)

## Installation

Clone the repository into a local folder.

    git clone https://github.com/vmray/sentinelone-singularity-vmray-connector.git

Install the requirements.

    pip install -r requirements.txt
    
Update the [conf.py](app/config/conf.py) file with your specific configurations.

## VMRay Configurations

- Create API Key with web interface. (`Analysis Settings > API Keys`)

- Edit the `VMRayConfig` class in [conf.py](app/config/conf.py) file.

| Configuration Item            | Description                                                 | Default                                              |
|:------------------------------|:------------------------------------------------------------|:-----------------------------------------------------|
| `API_KEY_TYPE`                | Enum for VMRay API Key Type [`REPORT`/`VERDICT`]            | `REPORT`                                             |
| `API_KEY`                     | API Key                                                     |                                                      |
| `URL`                         | URL of VMRay instance                                       | `https://eu.cloud.vmray.com`                         |
| `SSL_VERIFY`                  | Enable or disable certificate verification [`True`/`False`] | `True`                                               |
| `SUBMISSION_COMMENT`          | Comment for submitted samples                               | `Sample from VMRay Analyzer - SentinelOne Connector` |
| `SUBMISSION_TAGS`             | Tags for submitted samples                                  | `SentinelOne`                                        |
| `SEND_CUSTOM_SUBMISSION_TAGS` | Append custom tag for submitted samples                     | `False`                                              |
| `ANALYSIS_TIMEOUT`            | Timeout for submission analyses as seconds                  | `120`                                                |
| `ANALYSIS_JOB_TIMEOUT`        | Timeout for analysis job in wait_submissions as seconds     | `900`                                                |
| `CONNECTOR_NAME`              | Connector Name                                              | `SentinelOne`                                        |

## SentinelOne Configurations

- Generate an API Token with web interface. (`Settings > Users > Click your username > API Token Generate`)

- If API Token expired, regenerate an API Token with web interface. (`Settings > Users > Click your username > Options > Regenerate API Token`)

Note: API Token expiration period is 6 months. [More details](https://usea1-partners.sentinelone.net/docs/en/generating-api-tokens.html)

- Edit the 'SentinelOneConfig' class in [conf.py](app/config/conf.py) file.

| Configuration Item                               | Description                                                              | Default                                    |
|:-------------------------------------------------|:-------------------------------------------------------------------------|:-------------------------------------------|
| `API` > `API_TOKEN`                              | SentinelOne API Token                                                    |                                            |
| `API` > `HOSTNAME_URL`                           | Hostname to access SentinelOne                                           |                                            |
| `API` > `API_PREFIX`                             | API Prefix to create SentinelOne API URL                                 | `web/api/v2.1`                             |
| `API` > `USER_AGENT`                             | User-Agent value to use for SentinelOne                                  | `MdePartner-VMRay-VMRayAnalyzer/4.4.1`     |
| `API` > `MAX_DATA_COUNT`                         | Maximum data count that can be fetch in each request                     | `1000`                                     |
| `API` > `FETCH_FILE_TIMEOUT`                     | Timeout for fetch sample file as seconds                                 | `60`                                       |
| `API` > `FETCH_FILE_TIME_SPAN`                   | Time span for each fetch sample file as seconds                          | `10`                                       |
| `DOWNLOAD` > `DIR`                               | Download directory name                                                  | `downloads`                                |
| `PROCESS` > `FILTER_QUERY`                       | Filter Query to get processes                                            | `ObjectType = "Process"`                   |
| `INDICATOR` > `NAME`                             | Name for indicators which created by connector                           | `Indicator based on VMRay Analyzer Report` |
| `INDICATOR` > `DESCRIPTION`                      | Description for indicators which created by connector                    | `Indicator based on VMRay Analyzer Report` |
| `INDICATOR` > `SOURCE`                           | Source for indicators which created by connector                         | `Indicator based on VMRay Analyzer Report` |
| `BLACKLIST` > `AUTO_ADD_GLOBAL` > `ACTIVE`       | Automated add to global blacklist with SHA1 hash values [`True`/`False`] | `False`                                    |
| `BLACKLIST` > `AUTO_ADD_GLOBAL` > `VERDICTS`     | Selected verdicts to add to global blacklist automatically               | [`suspicious`,`malicious`]                 |
| `BLACKLIST` > `AUTO_ADD_GLOBAL` > `DESCRIPTION`  | Description for added to global blacklist automatically                  | `Indicator based on VMRay Analyzer Report` |
| `BLACKLIST` > `AUTO_ADD_THREAT` > `ACTIVE`       | Automated add to threat blacklist with SHA1 hash values [`True`/`False`] | `False`                                    |
| `BLACKLIST` > `AUTO_ADD_THEAT` > `VERDICTS`      | Selected verdicts to add to threat blacklist automatically               | [`suspicious`,`malicious`]                 |
| `BLACKLIST` > `AUTO_ADD_THREAT` > `DESCRIPTION`  | Description for added to threat blacklist automatically                  | `Indicator based on VMRay Analyzer Report` |
| `BLACKLIST` > `AUTO_ADD_WITH_DV` > `ACTIVE`      | Automated add to blacklist with SHA1 hash values [`True`/`False`]        | `False`                                    |
| `BLACKLIST` > `AUTO_ADD_WITH_DV` > `VERDICTS`    | Selected verdicts to add to blacklist with deep visibility automatically | [`suspicious`,`malicious`]                 |
| `ACTION` > `AUTO_KILL` > `ACTIVE`                | Automated kill process status [`True`/`False`]                           | `False`                                    |
| `ACTION` > `AUTO_KILL` > `VERDICTS`              | Selected verdicts to kill process automatically                          | [`suspicious`,`malicious`]                 |
| `ACTION` > `AUTO_QUARANTINE` > `ACTIVE`          | Automated add quarantine status [`True`/`False`]                         | `False`                                    |
| `ACTION` > `AUTO_QUARANTINE` > `VERDICTS`        | Selected verdicts to add quarantine automatically                        | [`suspicious`,`malicious`]                 |
| `ACTION` > `AUTO_DISCONNECT` > `ACTIVE`          | Automated disconnect machine from network status [`True`/`False`]        | `False`                                    |
| `ACTION` > `AUTO_DISCONNECT` > `VERDICTS`        | Selected verdicts to disconnect machine from network automatically       | [`suspicious`,`malicious`]                 |
| `ACTION` > `AUTO_SHUTDOWN` > `ACTIVE`            | Automated shutdown machine status [`True`/`False`]                       | `False`                                    |
| `ACTION` > `AUTO_SHUTDOWN` > `VERDICTS`          | Selected verdicts to shutdown machine automatically                      | [`suspicious`,`malicious`]                 |
| `ACTION` > `AUTO_INITIATE_SCAN` > `ACTIVE`       | Automated anti virus scan status [`True`/`False`]                        | `False`                                    |
| `ACTION` > `AUTO_INITIATE_SCAN` > `VERDICTS`     | Selected verdicts to anti virus scan automatically                       | [`suspicious`,`malicious`]                 |
| `TIME_SPAN`                                      | Alert polling time span as seconds                                       | `3600`                                     |
| `ACCOUNT_ID`                                     | SentinelOne Account ID for filtering                                     | `[]`                                       |
| `SITE_IDS`                                       | SentinelOne Site IDs for filtering                                       | `[]`                                       |
| `ZIP_PASSWORD`                                   | ZIP Password to use for download files                                   | `SentinelEvidenceFile.!`                   |
| `SUBMISSION_CUSTOM_TAG_PROPERTY`                 | Custom tag property for VMRay submission                                 | `siteId`                                   |

## General Connector Configurations

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

# Running the Connector

## Running with CLI

You can start connector with command line after completing the configurations. You need to set `RUNTIME_MODE` as `RUNTIME_MODE.CLI` in the `GeneralConfig`. Also, you can create cron job for continuous processing.
    
    python connector.py

## Running with Docker

You can create and start Docker image with Dockerfile after completing the configurations. You need to set `RUNTIME_MODE` as `RUNTIME_MODE.DOCKER` in the `GeneralConfig`.

    docker build -t s1_connector .
    docker run -d -v $(pwd)/log:/app/log -t s1_connector

After running the Docker container you can see connector logs in the log directory on your host machine.