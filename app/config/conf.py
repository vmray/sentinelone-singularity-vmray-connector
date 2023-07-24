import pathlib
import logging as log


class RUNTIME_MODE:
    DOCKER = "DOCKER"
    CLI = "CLI"


class REQUEST_METHOD:
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"


# VMRay verdicts enum
class VERDICT:
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


# VMRay job status
class JOB_STATUS:
    QUEUED = "queued"
    INWORK = "inwork"


# VMRay Configuration
class VMRayConfig:
    # VMRay Report or Verdict API KEY
    # For more effective usage of quota please use a Verdict API Key
    # The connector will automatically unlock the entire report if the verdict is non-clean
    API_KEY = ""

    # Unlock automatic report for Verdict of API key type
    AUTO_UNLOCK_REPORT = False

    # VMRay REST API URL
    URL = "https://eu.cloud.vmray.com"

    # SSL Verification setting for self-signed certificates
    SSL_VERIFY = True

    # VMRay Submission Comment
    SUBMISSION_COMMENT = "Sample from VMRay Analyzer - SentinelOne Connector"

    # VMRay submission tags (Can't contain space)
    SUBMISSION_TAGS = ["SentinelOne"]

    # Append a custom tag like SITE_ID or SITE_NAME to VMRay submission tags
    SEND_CUSTOM_SUBMISSION_TAGS = False

    # VMRay analysis timeout value (seconds)
    ANALYSIS_TIMEOUT = 120

    # VMRay analysis job timeout for wait_submissions
    ANALYSIS_JOB_TIMEOUT = 900

    # Connector Name
    CONNECTOR_NAME = "SentinelOne"

    # Connector Version
    CONNECTOR_VERSION = "1.0"

    # Resubmission status which has been already analyzed by VMRay
    RESUBMIT = False

    # Selected verdicts to resubmit evidences
    RESUBMISSION_VERDICTS = [VERDICT.MALICIOUS, VERDICT.SUSPICIOUS]


# Sample Types
class SAMPLE_TYPE:
    THREAT = 'threat'
    PROCESS = 'process'


# SentinelOne Activity Types
class ACTIVITY_TYPE:
    AGENT_UPLOADED_FETCHED_FILES = 80
    AGENT_UPLOADED_THREAT_FILE = 86


# SentinelOne Mitigation Types
class MITIGATION_TYPE:
    KILL = "kill"
    QUARANTINE = "quarantine"


# SentinelOne Site Properties for Custom Tag
class SITE_PROPERTIES:
    SITE_ID = "siteId"
    SITE_NAME = "siteName"


# SentinelOne Threat Note subtype enum
class NOTE_SUBTYPES:
    VERDICT = "verdict"
    VTI = "vti"
    IOC = "ioc"


# SentinelOne Threat Note IOC field enum
class NOTE_IOC_FIELDS:
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    IPV4 = "ipv4"
    DNS = "domain"
    URL = "url"


class COLLECT_METHODS:
    THREAT = "threat"
    DEEP_VISIBILITY = "deep-visibility"


class DOWNLOAD_METHODS:
    CLOUD = "download-cloud"
    FETCH_FROM_AGENT = "fetch-file"


# SentinelOne Configuration
class SentinelOneConfig:
    # Alert polling time span as seconds
    TIME_SPAN = 3600

    # Filter by account id
    # "" => to include the first or default account
    # example: "1236876387553034321"
    ACCOUNT_ID = ""

    # Filter by site id
    # [] => to include all sites
    # example: ["1116876387561422222", "2224027517108671444"]
    SITE_IDS = []

    # Used for zip file password
    ZIP_PASSWORD = "S1BinaryVault"

    # Custom Tag Property for VMRay Submission
    # To be able to use this you need to change the SEND_CUSTOM_SUBMISSION_TAGS property above to True
    SUBMISSION_CUSTOM_TAG_PROPERTY = SITE_PROPERTIES.SITE_NAME

    # Methods to be used to collect samples
    SELECTED_COLLECT_METHODS = [COLLECT_METHODS.THREAT]

    # API related configurations
    class API:
        # SentinelOne API, API Token
        # Used for programmatic API accesses
        # To learn more about temporary and 6-month tokens and how to generate them,
        # see https://support.sentinelone.com/hc/en-us/articles/360004195934.
        API_TOKEN = ""

        # Hostname to access SentinelOne
        HOSTNAME_URL = "https://usea1-partners.sentinelone.net"

        # Api Prefix to generate URL for SentinelOne API
        API_PREFIX = "web/api/v2.1"

        # URL to access SentinelOne for Endpoint API
        URL = "%s/%s" % (HOSTNAME_URL, API_PREFIX)

        # Authentication Url to authenticate SentinelOne
        AUTH_URL = "%s/users/login/by-api-token" % URL

        # User-Agent value to use for SentinelOne for Endpoint API
        USER_AGENT = "S1-VMRayAnalyzer-Connector"

        # Max data count per request
        # Max limit = 1.000
        MAX_DATA_COUNT = 1000

        # Fetch file timeout (seconds)
        FETCH_FILE_TIMEOUT = 60

        # Time span between request iteration (seconds)
        FETCH_FILE_TIME_SPAN = 10

    # Download related configurations
    class DOWNLOAD:
        # Download directory name
        DIR = pathlib.Path("downloads")

        # Download directory path
        ABSOLUTE_PATH = pathlib.Path(__file__).parent.parent.resolve() / DIR

        # Method to be used to download samples
        EVIDENCE_DOWNLOAD_METHOD = DOWNLOAD_METHODS.FETCH_FROM_AGENT

    # Process related configurations
    class PROCESS:
        # Process filter query
        FILTER_QUERY = 'ObjectType = "Process"'

    # Indicator related configurations
    # https://usea1-partners.sentinelone.net/docs/en/indicators.html
    class INDICATOR:
        # Title for indicators which created by connector
        NAME = "Indicator based on a VMRay Analyzer Report"

        # Description for indicators which created by connector
        DESCRIPTION = "Indicator based on a VMRay Analyzer Report"

        # Source for indicators which created by connector
        SOURCE = "VMRay"

    # Blacklist related configurations
    class BLACKLIST:
        # Add blacklist processes with SHA1 hash values
        class AUTO_ADD_GLOBAL:
            # Automated add blacklist processes with SHA1 hash values
            ACTIVE = False

            # Selected verdicts to blacklist processes automatically
            VERDICTS = [VERDICT.MALICIOUS]

            # Description for indicators which created by connector
            DESCRIPTION = "Reported from VMRay Analyzer"

        # Add blacklist processes with SHA1 hash values for threats
        class AUTO_ADD_THREAT:
            # Automated add blacklist processes with SHA1 hash values for threats
            ACTIVE = False

            # Selected verdicts to blacklist processes automatically for threats
            VERDICTS = [VERDICT.MALICIOUS]

            # Description for indicators which created by connector
            DESCRIPTION = "Reported from VMRay Analyzer"

        # Add blacklist processes with deep visibility
        class AUTO_ADD_WITH_DV:
            # Automated add blacklist processes with deep visibility
            ACTIVE = False

            # Selected verdicts to blacklist processes automatically with deep visibility
            VERDICTS = [VERDICT.MALICIOUS]

    # Endpoint Action related configurations
    class ACTION:
        # Threat kill to process
        class AUTO_KILL:
            # Automated threat kill to process status
            ACTIVE = False

            # Selected verdicts to kill threat process automatically
            VERDICTS = [VERDICT.MALICIOUS]

        # Threat add to quarantine
        class AUTO_QUARANTINE:
            # Automated threat add to quarantine
            ACTIVE = False

            # Selected verdicts to quarantine process automatically
            VERDICTS = [VERDICT.MALICIOUS]

        # Machine disk scan related configuration
        class AUTO_INITIATE_SCAN:
            # Automated machine disk scan status
            ACTIVE = False

            # Selected verdicts to disk scan to machine automatically
            VERDICTS = [VERDICT.MALICIOUS]

        # Machine disconnect from network related configuration
        class AUTO_DISCONNECT:
            # Automated machine disconnect from network status
            ACTIVE = False

            # Selected verdicts to machine disconnect from network automatically
            VERDICTS = [VERDICT.MALICIOUS]

        # Machine shutdown related configuration
        class AUTO_SHUTDOWN:
            # Automated machine shutdown status
            ACTIVE = False

            # Selected verdicts to machine shutdown automatically
            VERDICTS = [VERDICT.MALICIOUS]

    # Threat Note related configurations
    class NOTE:
        # Selected subtypes for processing
        SELECTED_SUBTYPES = [NOTE_SUBTYPES.VERDICT, NOTE_SUBTYPES.VTI, NOTE_SUBTYPES.IOC]

        # Selected ioc fields for processing
        SELECTED_IOC_FIELDS = [NOTE_IOC_FIELDS.MD5, NOTE_IOC_FIELDS.SHA1, NOTE_IOC_FIELDS.SHA256, NOTE_IOC_FIELDS.IPV4,
                               NOTE_IOC_FIELDS.DNS, NOTE_IOC_FIELDS.URL]


# General Configuration
class GeneralConfig:
    # Log directory
    LOG_DIR = pathlib.Path("log")

    # Log file path
    LOG_FILE_PATH = LOG_DIR / pathlib.Path("sentinelone-connector.log")

    # Log verbosity level
    LOG_LEVEL = log.INFO

    # Selected verdicts for processing
    SELECTED_VERDICTS = [VERDICT.MALICIOUS]

    # Time span between script iterations
    TIME_SPAN = 300

    # Runtime mode for script
    # If selected as CLI, script works only once, you need to create cron job for continuous processing
    # If selected as DOCKER, scripts works continuously with TIME_SPAN above
    RUNTIME_MODE = RUNTIME_MODE.DOCKER


# VMRay Analyzer and SentinelOne indicator field mappings
# You can enable or disable IOC values with comments
# https://usea1-partners.sentinelone.net/docs/en/indicators.html
IOC_FIELD_MAPPINGS = {
    "ipv4": ["IPV4"],

    "sha256": ["SHA256"],

    "domain": ["DNS"],

    "url": ["URL"],

    "sha1": ["SHA1"],

    "md5": ["MD5"],
}
