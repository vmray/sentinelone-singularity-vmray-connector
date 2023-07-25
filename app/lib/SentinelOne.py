import base64
import shutil
import zipfile
import os
import pathlib
from datetime import datetime, timedelta, timezone
import requests
import json
import time

from app.config.conf import SentinelOneConfig, ACTIVITY_TYPE, SAMPLE_TYPE, IOC_FIELD_MAPPINGS, REQUEST_METHOD, \
    NOTE_SUBTYPES, DOWNLOAD_METHODS, VERDICT


class SentinelOne:
    """
    Wrapper class for SentinelOne API calls.
    Import this class to retrieve processes, threats and extract SHA1 hashes.
    """

    def __init__(self, log):
        """
        Initialize and authenticate the SentinelOne instance, use SentinelOneConfig as config
        :param log: logger instance
        :return: void
        """
        self.headers = None
        self.config = SentinelOneConfig
        self.log = log

        self.authenticate()
        self.get_account()
        self.get_sites()

    def authenticate(self):
        """
        Authenticate the SentinelOne with the api token
        :raise: Exception when credentials/application properties are not properly configured
        :return: void
        """

        # defining request body with user api token
        body = {
            "data": {
                "apiToken": self.config.API.API_TOKEN,
                "reason": self.config.API.USER_AGENT
            }
        }

        # posting defined request data to retrieve access token
        try:
            response = requests.post(url=self.config.API.AUTH_URL, json=body)
            if response.status_code != 200:
                raise Exception("Authentication failed to SentinelOne")

            self.headers = {
                "Authorization": "ApiToken %s" % self.config.API.API_TOKEN,
                "User-Agent": self.config.API.USER_AGENT
            }
            self.log.debug("Successfully authenticated the SentinelOne")
        except Exception as err:
            self.log.error(err)
            raise

    def send_request(self, method, path, params=None, return_pagination=False):
        """
        Send request to the SentinelOne API
        :param method: request method type
        :param path: request path
        :param params: request parameters
        :param return_pagination: return pagination value
        :exception: when response are not properly retrieved
        :return result: response values
        """
        # try-except block for handling api request exceptions
        try:
            # making api call with get params and loading response as json
            request_url = self.config.API.URL + path

            if method == REQUEST_METHOD.POST:
                response = requests.post(url=request_url, json=params, headers=self.headers)
            elif method == REQUEST_METHOD.PUT:
                response = requests.put(url=request_url, json=params, headers=self.headers)
            elif method == REQUEST_METHOD.DELETE:
                response = requests.delete(url=request_url, params=params, headers=self.headers)
            elif method == REQUEST_METHOD.GET:
                response = requests.get(url=request_url, params=params, headers=self.headers)
            else:
                self.log.error("Request method is not valid.")
                return None

            json_response = json.loads(response.content)

            # if api response contains the "errors" key, should be an error about request
            if "errors" in json_response:
                for error in json_response["errors"]:
                    self.log.error("Failed to retrieve response data - Error: %s. %s" % (error["title"], error["detail"]))
            else:
                # value key in json response contains accounts
                # checking the "data" key as a second error control
                if "data" in json_response:
                    if return_pagination:
                        return json_response["data"], json_response.get("pagination", {})
                    else:
                        return json_response["data"]
                else:
                    self.log.error("Failed to parse api response - Error: value key not found in dict.")
        except Exception as err:
            self.log.error("Failed to retrieve response data - Error: %s" % err)
        return None

    def get_account(self):
        """
        Retrieve accounts
        https://usea1-partners.sentinelone.net/api-doc/api-details?category=accounts&api=get-accounts
        :exception: when account are not properly retrieved
        :return void:
        """
        request_path = "/accounts"

        if len(self.config.ACCOUNT_ID) == 0:
            result = self.send_request(REQUEST_METHOD.GET, request_path)

            if result and len(result) > 0:
                self.config.ACCOUNT_ID = result[0]["id"]
                self.log.info("Successfully retrieved account")
            else:
                self.log.error("Account not found.")
                raise Exception("Account not found.")
        else:
            params = {
                "accountIds": self.config.ACCOUNT_ID
            }
            result = self.send_request(REQUEST_METHOD.GET, request_path, params)

            if result and len(result) > 0:
                self.log.info("Successfully retrieved account")
            else:
                self.log.error("Account ID not found.")
                raise Exception("Account ID not found.")

    def get_sites(self):
        """
        Retrieve sites
        https://usea1-partners.sentinelone.net/api-doc/api-details?category=sites&api=get-sites
        :exception: when sites are not properly retrieved
        :return void:
        """
        request_path = "/sites"
        params = {
            "accountId": self.config.ACCOUNT_ID,
            "limit": self.config.API.MAX_DATA_COUNT
        }

        if len(self.config.SITE_IDS) > 0:
            site_ids = []
            for site_id in self.config.SITE_IDS:
                params["siteIds"] = site_id
                result = self.send_request(REQUEST_METHOD.GET, request_path, params)
                if result and "sites" in result and len(result["sites"]) > 0:
                    site_ids.append(result["sites"][0]["id"])
                else:
                    self.log.error("Site ID %s is not valid" % site_id)
            if len(site_ids) > 0:
                self.config.SITE_IDS = site_ids
            else:
                self.log.error("Site IDs are not valid.")
                raise Exception("Site IDs are not valid.")
        else:
            site_ids = []

            is_iterable = True
            while is_iterable:
                result, pagination = self.send_request(REQUEST_METHOD.GET, request_path, params, return_pagination=True)

                is_iterable = pagination.get("nextCursor")

                if result and "sites" in result and len(result["sites"]) > 0:
                    for s1_site in result["sites"]:
                        site_ids.append(s1_site["id"])

                    if is_iterable:
                        params["cursor"] = pagination["nextCursor"]

            if len(site_ids) == 0:
                self.log.error("Site(s) not found.")
                raise Exception("Site(s) not found.")

            self.config.SITE_IDS = site_ids
            self.log.info("Successfully retrieved sites")

    def is_agent_active(self, agent_id):
        """
        Retrieve agent status
        https://usea1-partners.sentinelone.net/api-doc/api-details?category=agents&api=get-agents
        :param agent_id: id of agent
        :exception: when threat and evidences are not properly retrieved
        :return status: boolean
        """
        params = {
            "accountIds": self.config.ACCOUNT_ID,
            "siteIds": ",".join(self.config.SITE_IDS),
            "sortBy": "createdAt",
            "sortOrder": "desc",
            "skip": 0,
            "limit": 1,
            "ids": agent_id,
        }

        request_path = "/agents"
        result = self.send_request(REQUEST_METHOD.GET, request_path, params)

        if result and len(result) > 0:
            # if return any activity, set activity variable
            return result[0]["isActive"]

        return False

    def get_evidences_from_threats(self):
        """
        Retrieve threat and related evidence information
        https://usea1-partners.sentinelone.net/api-doc/api-details?category=threats&api=get-threats
        :exception: when threat and evidences are not properly retrieved
        :return evidences: dictionary of evidence objects
        """

        # defining start_time for threats with using configured TIME_SPAN
        # we need to use UTC because SentinelOne stores timestamps as UTC
        start_time = (datetime.utcnow() - timedelta(seconds=self.config.TIME_SPAN)).strftime('%Y-%m-%dT%H:%M:%SZ')

        params = {
            "accountIds": self.config.ACCOUNT_ID,
            "siteIds": ",".join(self.config.SITE_IDS),
            "confidenceLevels": ",".join(self.config.SELECTED_CONFIDENCE_LEVELS),
            "sortBy": "createdAt",
            "sortOrder": "desc",
            "limit": self.config.API.MAX_DATA_COUNT,
            "createdAt__gt": start_time
        }

        request_path = "/threats"

        # defining initial dictionary which stores evidence objects
        evidences = {}

        is_iterable = True
        while is_iterable:
            result, pagination = self.send_request(REQUEST_METHOD.GET, request_path, params, return_pagination=True)

            is_iterable = pagination.get("nextCursor")

            if result:
                self.log.info("Successfully retrieved %d threats" % (len(result)))

                # iterating threats and retrieving evidence data to create Evidence objects
                for threat in result:
                    # try-except block for handling dictionary key related exceptions
                    try:
                        threat_details = threat["threatInfo"]
                        threat_details["id"] = threat["id"]
                        threat_details["agent_id"] = threat["agentRealtimeInfo"]["agentId"]
                        threat_details["download_url"] = ""
                        threat_details["download_method"] = ""
                        threat_details["sample_type"] = SAMPLE_TYPE.THREAT
                        threat_details["site_id"] = threat["agentRealtimeInfo"]["siteId"]
                        threat_details["site_name"] = threat["agentRealtimeInfo"]["siteName"]
                        threat_details["custom_tag"] = threat["agentRealtimeInfo"][self.config.SUBMISSION_CUSTOM_TAG_PROPERTY]
                        threat_id = threat["id"]

                        # if threat id is empty or none, continue
                        if threat_id is not None and threat_id != "":
                            # add threat information to dictionary if evidence dictionary doesn't have threat id
                            if threat_id not in evidences.keys():
                                evidences[threat_id] = threat_details
                    except Exception as err:
                        self.log.warning("Failed to parse threat object - Error: %s" % err)

                if is_iterable:
                    params["cursor"] = pagination["nextCursor"]

                self.log.info("Successfully retrieved %d evidences from %d threats" % (len(evidences), len(result)))
        return evidences

    def fetch_request_evidence_file(self, evidences):
        """
        Fetch request to generate evidence files' download links
        https://usea1-partners.sentinelone.net/api-doc/api-details?category=threats&api=fetch-threat-file
        https://usea1-partners.sentinelone.net/api-doc/api-details?category=activities&api=get-activities
        :param evidences: list of evidence objects
        :exception: when evidence download link is not generated
        :return evidences: list of evidence objects with download link
        """
        self.log.info("Download link generating for %d evidences" % len(evidences))

        for evidence_id, evidence in evidences.items():
            self.log.info("Sending request to fetch evidence file %s" % evidence["sha1"])

            params = {
                "data": {
                    "password": self.config.ZIP_PASSWORD
                },
                "filter": {
                    "ids": [
                        evidence_id
                    ]
                }
            }

            request_path = "/threats/fetch-file"
            result = self.send_request(REQUEST_METHOD.POST, request_path, params)

            if result:
                requested_date = datetime.utcnow()

                # Checking if agent is online to fetch file
                is_agent_online = self.is_agent_active(evidence["agent_id"])

                while is_agent_online:
                    params = {
                        "accountIds": self.config.ACCOUNT_ID,
                        "siteIds": ",".join(self.config.SITE_IDS),
                        "sortBy": "createdAt",
                        "sortOrder": "desc",
                        "skip": 0,
                        "limit": 1,
                        "activityTypes": ACTIVITY_TYPE.AGENT_UPLOADED_THREAT_FILE,
                        "threatIds": evidence_id
                    }

                    request_path = "/activities"
                    result = self.send_request(REQUEST_METHOD.GET, request_path, params)

                    if result and len(result) > 0:
                        activity = result[0]
                        # set download_url to evidence
                        evidence["download_url"] = self.config.API.URL + activity["data"]["downloadUrl"]
                        # set download_method to evidence
                        evidence["download_method"] = DOWNLOAD_METHODS.FETCH_FROM_AGENT
                        break

                    # Skip after timeout seconds if the server is not online or file is not returning.
                    if (datetime.utcnow() - requested_date).seconds >= self.config.API.FETCH_FILE_TIMEOUT:
                        self.log.error("Failed to fetch file request - Error: Timeout")
                        break
                    else:
                        time.sleep(self.config.API.FETCH_FILE_TIME_SPAN)
        return evidences

    def fetch_request_evidence_file_from_cloud(self, evidences):
        """
        Fetch request to generaet evidence files' download links
        https://usea1-partners.sentinelone.net/api-doc/api-details?category=threats&api=download-from-cloud
        :param evidences: list of evidence objects
        :exception: when evidence download link is not generated
        :return evidences: list of evidence objects with download link
        """
        self.log.info("Download link generating for %d evidences" % len(evidences))

        for evidence_id, evidence in evidences.items():
            self.log.info("Sending request to fetch evidence file %s" % evidence["sha1"])

            request_path = "/threats/%s/download-from-cloud" % evidence_id
            result = self.send_request(REQUEST_METHOD.GET, request_path)

            if result and 'downloadUrl' in result:
                # set download_url to evidence
                evidence["download_url"] = result["downloadUrl"]
                # set download_method to evidence
                evidence["download_method"] = DOWNLOAD_METHODS.CLOUD
            else:
                self.log.error("Failed to fetch file request")
        return evidences

    def get_process_from_dv(self):
        """
        Retrieve process information with deep visibility query
        https://usea1-partners.sentinelone.net/api-doc/api-details?category=deep-visibility&api=create-query-and-get-queryid
        https://usea1-partners.sentinelone.net/api-doc/api-details?category=deep-visibility&api=get-query-status
        https://usea1-partners.sentinelone.net/api-doc/api-details?category=deep-visibility&api=get-events
        :exception: when processes are not properly retrieved
        :return process: dictionary of process objects
        """

        # defining start_time for alerts with using configured TIME_SPAN
        # we need to use UTC because SentinelOne stores timestamps as UTC
        datetime_now = datetime.now(timezone.utc)
        utc_now = datetime_now.replace(tzinfo=timezone.utc)
        start_time = int(round((utc_now - timedelta(seconds=self.config.TIME_SPAN)).timestamp() * 1000))
        end_time = int(round(utc_now.timestamp() * 1000))

        params = {
            "accountIds": self.config.ACCOUNT_ID,
            "siteIds": ",".join(self.config.SITE_IDS),
            "query": self.config.PROCESS.FILTER_QUERY,
            "fromDate": start_time,
            "toDate": end_time,
            "skip": 0,
            "limit": self.config.API.MAX_DV_DATA_COUNT,
            "queryType": [
                "events"
            ],
            "isVerbose": False
        }

        request_path = "/dv/init-query"
        result = self.send_request(REQUEST_METHOD.POST, request_path, params)

        # defining initial dictionary which stores process objects
        processes = {}

        if result and "queryId" in result:
            query_id = result["queryId"]
            self.log.info("Successfully executed %s process query" % query_id)

            # Checking that the query is finished.
            query_status = "RUNNING"
            while query_status == "RUNNING":
                params = {
                    "queryId": query_id
                }

                request_path = "/dv/query-status"
                result = self.send_request(REQUEST_METHOD.GET, request_path, params)

                if result and "responseState" in result:
                    query_status = result["responseState"]
                    if query_status == "FINISHED":
                        break
                    elif "RUNNING" in query_status:
                        time.sleep(self.config.API.FETCH_FILE_TIME_SPAN)
                    else:
                        self.log.error("Failed to check query status: %s, query is not successful finished." % query_status)
                        break

            if query_status == "FINISHED":
                params = {
                    "queryId": query_id,
                    "sortBy": "createdAt",
                    "sortOrder": "desc",
                    "skip": 0,
                    "limit": self.config.API.MAX_DATA_COUNT
                }

                request_path = "/dv/events"
                result = self.send_request(REQUEST_METHOD.GET, request_path, params)

                if result:
                    # iterating query results of processes data to create Process objects
                    for process_data in result:
                        # try-except block for handling dictionary key related exceptions
                        try:
                            sha1 = process_data["processImageSha1Hash"]

                            # if process id is empty or none, continue
                            if sha1 is not None and sha1 != "":
                                # add threat information to dictionary if evidence dictionary doesn't have sha1 value
                                if sha1 not in processes.keys():
                                    processes[sha1] = {
                                        "sha1": process_data["processImageSha1Hash"],
                                        "agent_id": process_data["agentId"],
                                        "process_name": process_data["processName"],
                                        "process_path": process_data["processImagePath"],
                                        "site_id": process_data["siteId"],
                                        "site_name": process_data["siteName"],
                                        "custom_tag": process_data[self.config.SUBMISSION_CUSTOM_TAG_PROPERTY],
                                        "download_url": "",
                                        "download_method": "",
                                        "sample_type": SAMPLE_TYPE.PROCESS
                                    }
                        except Exception as err:
                            self.log.warning("Failed to parse process object - Error: %s" % err)

                self.log.info("Successfully retrieved %d process" % len(processes))
        return processes

    def fetch_request_process_file(self, processes):
        """
        Fetch request to generate process files' download link
        https://usea1-partners.sentinelone.net/api-doc/api-details?category=agent-actions&api=fetch-files
        https://usea1-partners.sentinelone.net/api-doc/api-details?category=activities&api=get-activities
        :param processes: list of process objects
        :exception: when process download link is not generated
        :return processes: list of process objects with download link
        """
        self.log.info("Download link generating for %d processes" % len(processes))
        for sha1, process in processes.items():
            self.log.info("Sending request to fetch process file %s" % sha1)

            params = {
                "data": {
                    "password": self.config.ZIP_PASSWORD,
                    "files": [
                        process["process_path"]
                    ]
                }
            }

            request_path = "/agents/%s/actions/fetch-files" % process["agent_id"]
            result = self.send_request(REQUEST_METHOD.POST, request_path, params)

            if result:
                # if value of "success" key is true, fetch request was successful
                requested_date = datetime.utcnow()

                # Checking if agent is online to fetch file
                is_agent_online = self.is_agent_active(process["agent_id"])

                while is_agent_online:
                    params = {
                        "accountIds": self.config.ACCOUNT_ID,
                        "siteIds": ",".join(self.config.SITE_IDS),
                        "sortBy": "createdAt",
                        "sortOrder": "desc",
                        "skip": 0,
                        "limit": 1,
                        "activityTypes": ACTIVITY_TYPE.AGENT_UPLOADED_FETCHED_FILES,
                        "agentIds": process["agent_id"],
                        "createdAt__gt": requested_date.strftime('%Y-%m-%dT%H:%M:%SZ'),
                    }

                    request_path = "/activities"
                    result = self.send_request(REQUEST_METHOD.GET, request_path, params)

                    if result and len(result) > 0:
                        # if return any activity, set activity variable
                        activity = result[0]
                        # set download_url to process
                        process["download_url"] = self.config.API.URL + activity["data"]["downloadUrl"]
                        # set download_method to process
                        process["download_method"] = DOWNLOAD_METHODS.FETCH_FROM_AGENT

                        self.log.info("File fetched successfully %s" % process["sha1"])
                        break

                    # Skip after timeout seconds if the server is not online or file is not returning.
                    if (datetime.utcnow() - requested_date).seconds >= self.config.API.FETCH_FILE_TIMEOUT:
                        self.log.error("Failed to fetch file request %s - Error: Timeout", process["sha1"])
                        break
                    else:
                        time.sleep(self.config.API.FETCH_FILE_TIME_SPAN)
        return processes

    def download_samples(self, samples):
        """
        Download and extract sample files
        :param samples: list of evidence/process objects
        :exception: when file is not properly downloaded or extracted
        :return samples: list of evidence/process objects with downloaded file_path
        """

        # initial list to store successfully downloaded samples
        downloaded_samples = []
        self.log.info("Downloading %d file" % len(samples))

        for sample_id, sample in samples.items():
            if sample["download_url"]:
                self.log.info("Downloading file %s" % sample["sha1"])

                # try-except block for handling download request errors
                try:
                    # download file and store it in response object
                    if sample["download_method"] == DOWNLOAD_METHODS.CLOUD:
                        response = requests.get(sample["download_url"])
                    else:
                        response = requests.get(sample["download_url"], stream=True, headers=self.headers)

                    # Check if the file was downloaded successfully
                    if response.ok:
                        self.log.info("File %s downloaded successfully." % sample["sha1"])
                    else:
                        self.log.info("Failed to download file %s. Status Code: %s" % (sample["sha1"], response.status_code))
                        continue

                    # initialize path variables for downloaded file
                    file_path = self.config.DOWNLOAD.ABSOLUTE_PATH / pathlib.Path(sample["sha1"] + ".zip")
                    unzipped_file_path = self.config.DOWNLOAD.ABSOLUTE_PATH / pathlib.Path(sample["sha1"])

                    # try-except block for handling file write errors
                    try:
                        # writing downloaded sample file into disk as chunks
                        with open(file_path, "wb") as file:
                            for chunk in response.iter_content(1024):
                                if chunk:
                                    file.write(chunk)
                        self.log.info("File %s saved successfully" % sample["sha1"])

                        # try-except block for handling zip extraction errors
                        try:
                            # extracting zip saved file
                            with zipfile.ZipFile(file_path, "r") as compressed:
                                compressed.extractall(pwd=bytes(self.config.ZIP_PASSWORD, "utf-8"), path=unzipped_file_path)

                            # if extracting successful, delete zip file
                            os.remove(file_path)
                            self.log.info("File %s extracted successfully" % sample["sha1"])

                            # read manifest.json to find sample file path
                            manifest_file_path = unzipped_file_path / pathlib.Path("manifest.json")
                            with open(manifest_file_path, "r") as manifest_file:
                                manifest_json_files = json.loads(manifest_file.read())
                                manifest_json_file = manifest_json_files[0]
                                if "reason" in manifest_json_file and manifest_json_file["reason"]:
                                    self.log.error("Failed to download file %s from client - Error: %s" % (sample["sha1"], manifest_json_file["reason"]))
                                    shutil.rmtree(unzipped_file_path, ignore_errors=True)
                                else:
                                    # set sample file path and append it to list
                                    file_path = manifest_json_file["path"].replace(":", "")
                                    if len(file_path) > 0:
                                        if file_path[0] == "\\":
                                            file_path = file_path[1:]
                                        file_path = file_path.replace("\\", os.sep)
                                        file_sha1_hash = manifest_json_file["sha1"]
                                        # Check the downloaded file hash is equal to the sample hash
                                        if file_sha1_hash == sample["sha1"]:
                                            sample["download_folder_path"] = unzipped_file_path
                                            sample["download_file_path"] = unzipped_file_path / pathlib.Path(file_path)
                                            downloaded_samples.append(sample)
                        except Exception as err:
                            self.log.error("Failed to extract file %s - Error: %s" % (sample["sha1"], err))
                    except Exception as err:
                        self.log.error("Failed to write file %s to %s - Error: %s" % (sample["sha1"], file_path, err))
                except Exception as err:
                    self.log.error("Failed to download file %s - Error: %s" % (sample["sha1"], err))
        return downloaded_samples

    def get_indicators(self):
        """
        Retrieve unique indicators from SentinelOne
        https://usea1-partners.sentinelone.net/api-doc/api-details?category=threat-intelligence&api=get-iocs
        :exception: when indicators are not properly retrieved
        :return indicators: set of indicators
        """

        params = {
            "sortBy": "creationTime",
            "sortOrder": "desc",
            "limit": self.config.API.MAX_DATA_COUNT,
        }

        request_path = "/threat-intelligence/iocs"

        # defining initial set for storing indicator values
        indicators = set()

        is_iterable = True
        while is_iterable:
            result, pagination = self.send_request(REQUEST_METHOD.GET, request_path, params, return_pagination=True)

            is_iterable = pagination.get("nextCursor")

            if result:
                for indicator in result:
                    # adding only value to check duplicates easily
                    indicators.add(indicator["value"])

                if is_iterable:
                    params["cursor"] = pagination["nextCursor"]

        self.log.info("%d unique indicator retrieved in total" % (len(indicators)))
        return indicators

    def create_indicator_objects(self, indicator_data, old_indicators, sample_data):
        """
        Create indicators objects based on VMRay Analyzer indicators
        :param indicator_data: dict of indicators which retrieved from VMRay submission
        :param old_indicators: set of indicators which retrieved from SentinelOne
        :param sample_data: dict object which contains summary data about sample
        :return indicator_objects: list of indicator objects
        """

        # we need to use UTC because SentinelOne stores timestamps as UTC
        creation_time = (datetime.utcnow()).strftime('%Y-%m-%dT%H:%M:%SZ')

        indicator_objects = []

        # iterate indicator types
        for key in indicator_data:

            # if configured IOC_FIELD_MAPPINGS dict has indicator type as key
            if key in IOC_FIELD_MAPPINGS.keys():

                # iterate IOC_FIELD_MAPPINGS values to map VMRay indicator types to SentinelOne
                for indicator_field in IOC_FIELD_MAPPINGS[key]:
                    indicator_value = indicator_data[key]

                    for indicator in indicator_value:
                        # duplicate check with old indicators
                        if indicator not in old_indicators:
                            indicator_objects.append({
                                "name": self.config.INDICATOR.NAME,
                                "description": self.config.INDICATOR.DESCRIPTION,
                                "method": "EQUALS",
                                "source": self.config.INDICATOR.SOURCE,
                                "type": indicator_field,
                                "value": indicator,
                                "creationTime": creation_time,
                                "reference": [sample_data["sample_webif_url"]]
                            })
        return indicator_objects

    def submit_indicators(self, indicators):
        """
        Submit indicators to SentinelOne
        https://usea1-partners.sentinelone.net/api-doc/api-details?category=threat-intelligence&api=create-iocs
        :param indicators: list of indicator objects
        :exception: when indicators are not submitted properly
        :return void:
        """
        self.log.info("%d indicators submitting to SentinelOne" % len(indicators))

        for indicator in indicators:
            params = {
                "data": [
                    indicator
                ],
                "filter": {
                    "accountIds": [self.config.ACCOUNT_ID],
                    "siteIds": self.config.SITE_IDS,
                }
            }

            request_path = "/threat-intelligence/iocs"
            result = self.send_request(REQUEST_METHOD.POST, request_path, params)

            if result:
                self.log.debug("Indicator %s submitted successfully" % indicator["value"])
            else:
                self.log.error("Failed to submit indicator %s" % indicator["value"])

    def get_notes(self, threat_id):
        """
        Retrieve notes from threats
        https://usea1-partners.sentinelone.net/api-doc/api-details?category=threat-notes&api=get-threat-notes
        :param threat_id: threat id of sample
        :exception: when note is not updated properly
        :return notes: list of note objects
        """

        params = {
            "sortBy": "createdAt",
            "sortOrder": "desc",
            "limit": self.config.API.MAX_DATA_COUNT,
        }

        request_path = "/threats/%s/notes" % threat_id

        # defining initial dictionary which stores notes objects
        notes = {}

        is_iterable = True
        while is_iterable:
            result, pagination = self.send_request(REQUEST_METHOD.GET, request_path, params, return_pagination=True)

            is_iterable = pagination.get("nextCursor")

            if result:
                # iterating threats and retrieving evidence data to create Note objects
                for note in result:
                    # try-except block for handling dictionary key related exceptions
                    try:
                        note_text = note["text"]
                        note_base64 = base64.b64encode(note_text.encode('ascii'))
                        notes[note_base64] = note_text
                    except Exception as err:
                        self.log.warning("Failed to parse note object - Error: %s" % err)

                if is_iterable:
                    params["cursor"] = pagination["nextCursor"]
        return notes

    def create_note(self, threat_id, sample_data, sample_vtis, sample_iocs):
        """
        Enrich threats with VMRay Analyzer submission metadata
        https://usea1-partners.sentinelone.net/api-doc/api-details?category=threat-notes&api=add-note-to-multiple
        :param threat_id: threat id of sample
        :param sample_data: dict object which contains summary data about the sample
        :param sample_vtis: dict object which contains parsed VTI data about the sample
        :exception: when note is not updated properly
        :return void:
        """

        # building note object as text

        # adding evidence sha1
        note = "Evidence SHA1:\n"
        note += sample_data["sample_sha1hash"] + "\n\n"

        # adding VMRay Analyzer Verdict
        if NOTE_SUBTYPES.VERDICT in self.config.NOTE.SELECTED_SUBTYPES:
            note += "VMRay Analyzer Verdict: \n%s\n\n" % sample_data["sample_verdict"].upper()

        # adding VMRay Analyzer sample url
        note += "Sample Url:\n"
        note += sample_data["sample_webif_url"] + "\n\n"

        # if sample is clean and automatic update analyst verdict enabled, adding false positive verdict note
        if sample_data["sample_verdict"] == VERDICT.CLEAN and self.config.THREAT.AUTO_UPDATE_FALSE_POSITIVE_VERDICT.ACTIVE:
            note += "%s\n\n" % self.config.THREAT.AUTO_UPDATE_FALSE_POSITIVE_VERDICT.DESCRIPTION
        else:
            # adding VMRay Analyzer sample classifications
            note += "Classifications:\n"
            note += "\n".join(sample_data["sample_classifications"]) + "\n\n"

            # adding VMRay Analyzer threat names
            note += "Threat Names:\n"
            note += "\n".join(sample_data["sample_threat_names"]) + "\n\n"

            # adding VMRay Analyzer VTI's
            if NOTE_SUBTYPES.VTI in self.config.NOTE.SELECTED_SUBTYPES:
                note += "VTI's:\n"
                note += "\n".join(list({vti['operation']: vti for vti in sample_vtis})) + "\n\n"

            # adding VMRay Analyzer IOC's
            if NOTE_SUBTYPES.IOC in self.config.NOTE.SELECTED_SUBTYPES:
                note += "IOC's:\n"
                ioc_note = []
                for key, value in sample_iocs.items():
                    if key in self.config.NOTE.SELECTED_IOC_FIELDS:
                        if len(value) > 0:
                            ioc_note.append(key.upper() + ": " + ", ".join(value))
                        else:
                            ioc_note.append(key.upper() + ": -")
                note += "\n".join(ioc_note) + "\n\n"

        # Checking whether note is in the threat
        threat_notes = self.get_notes(threat_id)
        note_base64 = base64.b64encode(note.encode('ascii'))

        if note_base64 not in threat_notes:
            params = {
                "data": {
                    "text": note
                },
                "filter": {
                    "accountIds": [self.config.ACCOUNT_ID],
                    "siteIds": self.config.SITE_IDS,
                    "ids": [
                        threat_id
                    ]
                }
            }

            request_path = "/threats/notes"
            result = self.send_request(REQUEST_METHOD.POST, request_path, params)

            if result and "affected" in result and result["affected"] > 0:
                self.log.debug("Threat note %s added successfully" % threat_id)
            else:
                self.log.error("Failed to add threat note %s" % threat_id)

    def auto_mitigate_threat(self, threat_id, agent_id, mitigate_type):
        """
        Mitigate threat with SentinelOne
        https://usea1-partners.sentinelone.net/api-doc/api-details?category=threats&api=mitigate-threats
        :param threat_id: id value of threat
        :param agent_id: id value of agent
        :param mitigate_type: type value of mitigation
        :return: void
        """
        params = {
            "filter": {
                "accountIds": [self.config.ACCOUNT_ID],
                "siteIds": self.config.SITE_IDS,
                "ids": [agent_id]
            }
        }

        request_path = "/threats/mitigate/%s" % mitigate_type
        result = self.send_request(REQUEST_METHOD.POST, request_path, params)

        if result and "affected" in result and result["affected"] > 0:
            self.log.debug("Threat %s mitigating(%s) is successfully" % (threat_id, mitigate_type))
        else:
            self.log.error("Threat %s mitigating(%s) is not successful" % (threat_id, mitigate_type))

    def auto_add_blacklist_threat(self, sha1):
        """
        Add malicious or suspicious processes' SHA1 hash to Blacklist with Deep Visibility
        https://usea1-partners.sentinelone.net/api-doc/api-details?category=threats&api=add-to-blacklist
        :param sha1: Hash value of sample
        :return: void
        """

        params = {
            "data": {
                "targetScope": "account",
                "description": self.config.BLACKLIST.AUTO_ADD_THREAT.DESCRIPTION
            },
            "filter": {
                "accountIds": [self.config.ACCOUNT_ID],
                "siteIds": self.config.SITE_IDS,
                "contentHashes": [
                    sha1
                ]
            }
        }

        request_path = "/threats/add-to-blacklist"
        result = self.send_request(REQUEST_METHOD.POST, request_path, params)

        if result and "affected" in result and result["affected"] > 0:
            self.log.debug("Sample %s added to blacklist threat successfully" % sha1)
        else:
            self.log.error("Sample %s not added to blacklist threat" % sha1)

    def is_blacklisted_global(self, value):
        """
        Get blacklisted items from SentinelOne with SHA1 hash
        https://usea1-partners.sentinelone.net/api-doc/api-details?category=exclusions-and-blacklist&api=get-blacklist
        :param value: Value of sample
        :return: boolean
        """

        params = {
            "accountIds": self.config.ACCOUNT_ID,
            "siteIds": ",".join(self.config.SITE_IDS),
            "value": value
        }

        request_path = "/restrictions"
        result = self.send_request(REQUEST_METHOD.GET, request_path, params)

        if result and len(result) > 0:
            return True
        else:
            return False

    def auto_add_blacklist_global(self, sha1, filetype):
        """
        Add malicious or suspicious processes' SHA1 hash to Blacklist
        https://usea1-partners.sentinelone.net/api-doc/api-details?category=exclusions-and-blacklist&api=create-blacklist-item
        :param sha1: Hash value of sample
        :param filetype: File type of sample
        :return: void
        """

        if not self.is_blacklisted_global(sha1):
            os_type = "windows"
            if "macOS" in filetype:
                os_type = "macos"
            elif "Linux" in filetype:
                os_type = "linux"

            params = {
                "data": {
                    "type": "black_hash",
                    "description": self.config.BLACKLIST.AUTO_ADD_GLOBAL.DESCRIPTION,
                    "osType": os_type,
                    "value": sha1,
                },
                "filter": {
                    "accountIds": [self.config.ACCOUNT_ID],
                    "siteIds": self.config.SITE_IDS,
                }
            }

            request_path = "/restrictions"
            result = self.send_request(REQUEST_METHOD.POST, request_path, params)

            if result and len(result) > 0:
                self.log.debug("Sample %s added to global blacklist successfully" % sha1)
            else:
                self.log.error("Sample %s not added global blacklist" % sha1)

    def auto_add_blacklist_with_dv(self, sha1, agent_id):
        """
        Add malicious or suspicious processes' SHA1 hash to Blacklist with Deep Visibility
        https://usea1-partners.sentinelone.net/api-doc/api-details?category=threats&api=add-to-blacklist-(deep-visibility)
        :param sha1: Hash value of sample
        :param agent_id: Agent id which has malicious or suspicious processes
        :return: void
        """

        params = {
            "data": {
                "targetScope": "account",
                "hashes": [
                    {
                        "agentId": agent_id,
                        "hash": sha1
                    }
                ]
            }
        }

        request_path = "/threats/dv-add-to-blacklist"
        result = self.send_request(REQUEST_METHOD.POST, request_path, params)

        if result and "affected" in result and result["affected"] > 0:
            self.log.debug("Sample %s added to blacklist with deep visibility successfully" % sha1)
        else:
            self.log.error("Sample %s not added blacklist with deep visibility" % sha1)

    def auto_disconnect_from_network(self, agent_id):
        """
        Disconnect the machine from network which has malicious or suspicious processes
        https://usea1-partners.sentinelone.net/api-doc/api-details?category=agent-actions&api=disconnect-from-network
        :param agent_id: Agent id which has malicious or suspicious processes
        :return: void
        """

        params = {
            "data": {},
            "filter": {
                "accountIds": [self.config.ACCOUNT_ID],
                "siteIds": self.config.SITE_IDS,
                "ids": [agent_id]
            }
        }

        request_path = "/agents/actions/disconnect"
        result = self.send_request(REQUEST_METHOD.POST, request_path, params)

        if result and "affected" in result and result["affected"] > 0:
            self.log.debug("Agent %s disconnect from network successfully" % agent_id)
        else:
            self.log.error("Failed agent(%s) disconnect from network" % agent_id)

    def auto_shutdown_machine(self, agent_id):
        """
        Shutdown the machine which has malicious or suspicious process
        https://usea1-partners.sentinelone.net/api-doc/api-details?category=agent-actions&api=shutdown
        :param agent_id: Agent id which has malicious or suspicious processes
        :return: void
        """

        params = {
            "data": {},
            "filter": {
                "accountIds": [self.config.ACCOUNT_ID],
                "siteIds": self.config.SITE_IDS,
                "ids": [agent_id]
            }
        }

        request_path = "/agents/actions/shutdown"
        result = self.send_request(REQUEST_METHOD.POST, request_path, params)

        if result and "affected" in result and result["affected"] > 0:
            self.log.debug("Agent %s shutdown successfully" % agent_id)
        else:
            self.log.error("Failed agent(%s) shutdown" % agent_id)

    def auto_disk_scan(self, agent_id):
        """
        Run disk scan action on agent which detected process as malicious or suspicious
        https://usea1-partners.sentinelone.net/api-doc/api-details?category=agent-actions&api=initiate-scan
        :param agent_id: Agent id which has malicious or suspicious processes
        :return: void
        """

        params = {
            "data": {},
            "filter": {
                "accountIds": [self.config.ACCOUNT_ID],
                "siteIds": self.config.SITE_IDS,
                "ids": [agent_id]
            }
        }

        request_path = "/agents/actions/initiate-scan"
        result = self.send_request(REQUEST_METHOD.POST, request_path, params)

        if result and "affected" in result and result["affected"] > 0:
            self.log.debug("Agent %s start disk scan successfully" % agent_id)
        else:
            self.log.error("Failed agent(%s) disk scan" % agent_id)

    def update_analyst_verdict(self, threat_id, verdict_type):
        """
        Update analyst verdict on threat
        https://usea1-partners.sentinelone.net/api-doc/api-details?category=threats&api=update-threat-analyst-verdict
        :param threat_id: id value of threat
        :param verdict_type: type value of verdict
        :return: void
        """
        params = {
            "data": {
                "analystVerdict": verdict_type
            },
            "filter": {
                "accountIds": [self.config.ACCOUNT_ID],
                "siteIds": self.config.SITE_IDS,
                "ids": [threat_id]
            }
        }

        request_path = "/threats/analyst-verdict"
        result = self.send_request(REQUEST_METHOD.POST, request_path, params)

        if result and "affected" in result and result["affected"] > 0:
            self.log.debug("Threat %s verdict(%s) update is successfully" % (threat_id, verdict_type))
        else:
            self.log.error("Threat %s verdict(%s) update is not successful" % (threat_id, verdict_type))
