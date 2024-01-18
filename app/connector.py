import os
import sys
import logging as log
import shutil
import time

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), os.pardir))


def run():
    if not GeneralConfig.LOG_DIR.exists():
        GeneralConfig.LOG_DIR.mkdir()

    if not GeneralConfig.LOG_FILE_PATH.exists():
        GeneralConfig.LOG_FILE_PATH.touch()

    if not SentinelOneConfig.DOWNLOAD.DIR.exists():
        SentinelOneConfig.DOWNLOAD.ABSOLUTE_PATH.mkdir()

    # Configure logging
    log.basicConfig(filename=GeneralConfig.LOG_FILE_PATH,
                    format='[%(asctime)s] [<pid:%(process)d> %(filename)s:%(lineno)s %(funcName)s] %(levelname)s %(message)s',
                    level=GeneralConfig.LOG_LEVEL)
    log.info('[CONNECTOR.PY] Started VMRay Analyzer Connector for SentinelOne')

    # Initializing and authenticating api instances
    sentinel = SentinelOne(log)
    vmray = VMRay(log)

    # Dict of evidences which found on VMRay database
    found_evidences = {}

    # Array of evidences which need to be downloaded from SentinelOne
    downloaded_evidences = []

    # Dict of retrieving evidences from SentinelOne
    evidences = {}

    # Unique evidence file sha1 values
    evidence_sha1_values = set()

    # Checking the selected collection method
    if COLLECT_METHODS.THREAT in SentinelOneConfig.SELECTED_COLLECT_METHODS:
        # Dict of evidences which need to be downloaded from SentinelOne
        download_evidences = {}

        # Dict of evidences which found on VMRay database but will be resubmitted
        resubmit_evidences = {}

        # Retrieving evidences from SentinelOne
        evidences = sentinel.get_evidences_from_threats()

        # Checking hash values in VMRay database
        for evidence_id, evidence in evidences.items():
            sample = vmray.get_sample(evidence["sha1"])
            evidence["sample"] = sample
            evidence_sha1_values.add(evidence["sha1"])
            if sample is not None:
                sample_data = vmray.parse_sample_data(sample)

                # if resubmission is active and sample verdicts in configured resubmission verdicts
                if vmray.config.RESUBMIT and sample_data['sample_verdict'] in vmray.config.RESUBMISSION_VERDICTS:
                    # File added into resubmit samples and re-analyzed
                    resubmit_evidences[evidence_id] = evidence
                # or if evidence is found on VMRay no need to submit again
                else:
                    # if evidence found on VMRay we need to store sample metadata in Evidence object
                    found_evidences[evidence_id] = evidence
            else:
                download_evidences[evidence_id] = evidence

        log.info("%d evidences found on VMRay database" % len(found_evidences))
        log.info("%d evidences found on VMRay database, but will be resubmitted" % len(resubmit_evidences))
        log.info("%d evidences need to be downloaded and submitted" % len(download_evidences))

        # Fetch request to generate evidence files' download link from SentinelOne
        # if evidence download method is cloud generate link from cloud endpoint
        if sentinel.config.DOWNLOAD.EVIDENCE_DOWNLOAD_METHOD == DOWNLOAD_METHODS.CLOUD:
            fetched_evidences = sentinel.fetch_request_evidence_file_from_cloud({**download_evidences, **resubmit_evidences})
        # if evidence download method is fetch-file generate link from agent
        else:
            fetched_evidences = sentinel.fetch_request_evidence_file({**download_evidences, **resubmit_evidences})

        # Download evidence files from SentinelOne
        downloaded_evidences = sentinel.download_samples(fetched_evidences)
        log.info("%d evidence file downloaded successfully" % len(downloaded_evidences))

    # Dict of processes which found on VMRay database
    found_processes = {}

    # Array of processes which need to be downloaded from SentinelOne
    downloaded_processes = []

    # Dict of retrieving processes from SentinelOne
    processes = {}

    # Checking the selected collection method
    if COLLECT_METHODS.DEEP_VISIBILITY in SentinelOneConfig.SELECTED_COLLECT_METHODS:
        # Dict of processes which need to be downloaded from SentinelOne
        download_processes = {}

        # Dict of processes which found on VMRay database but will be resubmitted
        resubmit_processes = {}

        # Retrieving processes from SentinelOne
        processes = sentinel.get_process_from_dv()

        # Checking hash values in VMRay database, if process file is found on VMRay no need to submit again
        for sha1, process in processes.items():
            # If this process file exists as evince file, pass.
            if sha1 not in evidence_sha1_values:
                sample = vmray.get_sample(sha1)
                process["sample"] = sample
                if sample is not None:
                    sample_data = vmray.parse_sample_data(sample)

                    # if resubmission is active and sample verdicts in configured resubmission verdicts
                    if vmray.config.RESUBMIT and sample_data['sample_verdict'] in vmray.config.RESUBMISSION_VERDICTS:
                        # File added into resubmit samples and re-analyzed
                        resubmit_processes[sha1] = process
                    # or if process is found on VMRay no need to submit again
                    else:
                        # if process file found on VMRay we need store sample metadata in Process object
                        found_processes[sha1] = process
                else:
                    download_processes[sha1] = process

        log.info("%d process file found on VMRay database" % len(found_processes))
        log.info("%d process file found on VMRay database, but will be resubmitted" % len(resubmit_processes))
        log.info("%d process file need to be downloaded and submitted" % len(download_processes))

        # Fetch request to generate process files download link from SentinelOne
        fetched_processes = sentinel.fetch_request_process_file({**download_processes, **found_processes})
        # Download process files from SentinelOne
        downloaded_processes = sentinel.download_samples(fetched_processes)
        log.info("%d process file downloaded successfully" % len(downloaded_processes))

    # Merge found and downloaded dictionaries
    found_samples = {**found_processes, **found_evidences}
    downloaded_samples = downloaded_evidences + downloaded_processes

    old_indicators = set()
    # If Indicator active automatic get active IOCs
    if SentinelOneConfig.INDICATOR.ACTIVE:
        # Retrieving indicators from SentinelOne to check duplicates
        old_indicators = sentinel.get_indicators()

    # Retrieving indicators from VMRay Analyzer for found evidences
    for found_sample in found_samples.values():
        sample = found_sample
        sample_data = vmray.parse_sample_data(sample["sample"])

        # If sample identified as suspicious or malicious
        # we need to extract indicator values and import them to SentinelOne
        if sample_data["sample_verdict"] in GeneralConfig.SELECTED_VERDICTS:
            # If api key type is Verdict, unlocking reports.
            if vmray.config.AUTO_UNLOCK_REPORT:
                vmray.unlock_reports(sample_data["sample_id"])

            # Retrieving and parsing indicators
            sample_iocs = vmray.get_sample_iocs(sample_data)
            ioc_data = vmray.parse_sample_iocs(sample_iocs)

            # If Indicator active automatic add new IOCs
            if SentinelOneConfig.INDICATOR.ACTIVE:
                # Creating SentinelOne IOC objects for IOC values
                indicator_objects = sentinel.create_indicator_objects(ioc_data, old_indicators, sample_data)

                # Submitting new indicators to SentinelOne
                sentinel.submit_indicators(indicator_objects)

            # If sample marked as threat by SentinelOne, add a note with vtis and sample metadata
            if sample["sample_type"] == SAMPLE_TYPE.THREAT:
                # Retrieving and parsing sample vtis from VMRay Analyzer
                vti_data = vmray.get_sample_vtis(sample_data["sample_id"])
                sample_vtis = vmray.parse_sample_vtis(vti_data)
                sentinel.create_note(sample["id"], sample_data, sample_vtis, ioc_data)

            # Adding sample sha1 to global
            if sentinel.config.BLACKLIST.AUTO_ADD_GLOBAL.ACTIVE:
                if sample_data["sample_verdict"] in sentinel.config.BLACKLIST.AUTO_ADD_GLOBAL.VERDICTS:
                    sentinel.auto_add_blacklist_global(sample["sha1"], sample_data['sample_type'])

            # Adding sample sha1 for threats
            if sentinel.config.BLACKLIST.AUTO_ADD_THREAT.ACTIVE:
                if sample_data["sample_verdict"] in sentinel.config.BLACKLIST.AUTO_ADD_THREAT.VERDICTS:
                    sentinel.auto_add_blacklist_threat(sample["sha1"])

            # Adding sample sha1 with Deep Visibility
            if sentinel.config.BLACKLIST.AUTO_ADD_WITH_DV.ACTIVE:
                if sample_data["sample_verdict"] in sentinel.config.BLACKLIST.AUTO_ADD_WITH_DV.VERDICTS:
                    sentinel.auto_add_blacklist_with_dv(sample["sha1"], sample['agent_id'])

            # Mitigating threat with Kill Process action
            if sentinel.config.ACTION.AUTO_KILL.ACTIVE:
                if sample["sample_type"] == SAMPLE_TYPE.THREAT and sample_data["sample_verdict"] in sentinel.config.ACTION.AUTO_KILL.VERDICTS:
                    sentinel.auto_mitigate_threat(sample["id"], sample['agent_id'], MITIGATION_TYPE.KILL)

            # Mitigating threat with Quarantine File action
            if sentinel.config.ACTION.AUTO_QUARANTINE.ACTIVE:
                if sample["sample_type"] == SAMPLE_TYPE.THREAT and sample_data["sample_verdict"] in sentinel.config.ACTION.AUTO_QUARANTINE.VERDICTS:
                    sentinel.auto_mitigate_threat(sample["id"], sample['agent_id'], MITIGATION_TYPE.QUARANTINE)

            # Running disk scan action
            if sentinel.config.ACTION.AUTO_INITIATE_SCAN.ACTIVE:
                if sample_data["sample_verdict"] in sentinel.config.ACTION.AUTO_INITIATE_SCAN.VERDICTS:
                    sentinel.auto_disk_scan(sample["agent_id"])

            # Disconnecting the machine from network
            if sentinel.config.ACTION.AUTO_DISCONNECT.ACTIVE:
                if sample_data["sample_verdict"] in sentinel.config.ACTION.AUTO_DISCONNECT.VERDICTS:
                    sentinel.auto_disconnect_from_network(sample["agent_id"])

            # Shutting down the machine
            if sentinel.config.ACTION.AUTO_SHUTDOWN.ACTIVE:
                if sample_data["sample_verdict"] in sentinel.config.ACTION.AUTO_SHUTDOWN.VERDICTS:
                    sentinel.auto_shutdown_machine(sample["agent_id"])

        # If sample identified as clean from VMRay
        elif sample_data["sample_verdict"] == VERDICT.CLEAN:
            # If sample marked as threat by SentinelOne and auto update verdict enabled,
            # add a note and update analyst verdict as false positive
            if sentinel.config.THREAT.AUTO_UPDATE_FALSE_POSITIVE_VERDICT.ACTIVE \
            and sample["sample_type"] == SAMPLE_TYPE.THREAT \
            and sample["confidenceLevel"] in sentinel.config.THREAT.AUTO_UPDATE_FALSE_POSITIVE_VERDICT.VERDICTS:
                sentinel.update_analyst_verdict(sample["id"], ANALYST_VERDICTS.FALSE_POSITIVE)
                sentinel.create_note(sample["id"], sample_data, sample_vtis={}, sample_iocs={})

    # Submitting downloaded samples to VMRay
    submissions = vmray.submit_samples(downloaded_samples)

    # Waiting and processing submissions
    for result in vmray.wait_submissions(submissions):
        submission = result["submission"]
        vmray.check_submission_error(submission)

        if result["finished"]:
            sample = vmray.get_sample(submission["sample_id"], True)
            sample_data = vmray.parse_sample_data(sample)

            # If sample identified as suspicious or malicious
            # we need to extract IOC values and import them to SentinelOne
            if sample_data["sample_verdict"] in GeneralConfig.SELECTED_VERDICTS:
                # Retrieving sample object value from evidence and process
                evidence_object = next((file for file in evidences.values() if file['sha1'] == sample_data["sample_sha1hash"]), None)
                process_object = next((file for file in processes.values() if file['sha1'] == sample_data["sample_sha1hash"]), None)

                # If api key type is Verdict, unlocking reports.
                if vmray.config.AUTO_UNLOCK_REPORT:
                    vmray.unlock_reports(sample_data["sample_id"])

                # Retrieving and parsing indicators
                sample_iocs = vmray.get_sample_iocs(sample_data)
                ioc_data = vmray.parse_sample_iocs(sample_iocs)

                # If Indicator active automatic add new IOCs
                if SentinelOneConfig.INDICATOR.ACTIVE:
                    # Creating SentinelOne IOC objects for IOC values
                    indicator_objects = sentinel.create_indicator_objects(ioc_data, old_indicators, sample_data)

                    # Submitting new indicators to SentinelOne
                    sentinel.submit_indicators(indicator_objects)

                # Getting sample object from evidence list or process list
                threat_sample = None
                if evidence_object:
                    threat_sample = evidences[evidence_object["id"]]
                elif process_object:
                    threat_sample = processes[process_object["id"]]

                # if SentinelOne has this threat add a note with vtis and sample metadata
                if evidence_object:
                    # Retrieving and parsing sample vtis from VMRay Analyzer
                    vti_data = vmray.get_sample_vtis(sample_data["sample_id"])
                    sample_vtis = vmray.parse_sample_vtis(vti_data)
                    sentinel.create_note(threat_sample["id"], sample_data, sample_vtis, ioc_data)

                # Adding sample sha1 to global
                if sentinel.config.BLACKLIST.AUTO_ADD_GLOBAL.ACTIVE:
                    if sample_data["sample_verdict"] in sentinel.config.BLACKLIST.AUTO_ADD_GLOBAL.VERDICTS:
                        sentinel.auto_add_blacklist_global(threat_sample["sha1"], sample_data['sample_type'])

                # Adding sample sha1 for threats
                if sentinel.config.BLACKLIST.AUTO_ADD_THREAT.ACTIVE:
                    if sample_data["sample_verdict"] in sentinel.config.BLACKLIST.AUTO_ADD_THREAT.VERDICTS:
                        sentinel.auto_add_blacklist_threat(threat_sample["sha1"])

                # Adding sample sha1 with Deep Visibility
                if sentinel.config.BLACKLIST.AUTO_ADD_WITH_DV.ACTIVE:
                    if sample_data["sample_verdict"] in sentinel.config.BLACKLIST.AUTO_ADD_WITH_DV.VERDICTS:
                        sentinel.auto_add_blacklist_with_dv(threat_sample["sha1"], threat_sample["agent_id"])

                # Mitigating threat with Kill Process action
                if sentinel.config.ACTION.AUTO_KILL.ACTIVE:
                    if evidence_object and sample_data["sample_verdict"] in sentinel.config.ACTION.AUTO_KILL.VERDICTS:
                        sentinel.auto_mitigate_threat(threat_sample["id"], threat_sample['agent_id'], MITIGATION_TYPE.KILL)

                # Mitigating threat with Quarantine File
                if sentinel.config.ACTION.AUTO_QUARANTINE.ACTIVE:
                    if evidence_object and sample_data["sample_verdict"] in sentinel.config.ACTION.AUTO_QUARANTINE.VERDICTS:
                        sentinel.auto_mitigate_threat(threat_sample["id"], threat_sample['agent_id'], MITIGATION_TYPE.QUARANTINE)

                # Running disk scan action
                if sentinel.config.ACTION.AUTO_INITIATE_SCAN.ACTIVE:
                    if threat_sample and sample_data["sample_verdict"] in sentinel.config.ACTION.AUTO_INITIATE_SCAN.VERDICTS:
                        sentinel.auto_disk_scan(threat_sample["agent_id"])

                # Disconnecting the machine from network
                if sentinel.config.ACTION.AUTO_DISCONNECT.ACTIVE:
                    if threat_sample and sample_data["sample_verdict"] in sentinel.config.ACTION.AUTO_DISCONNECT.VERDICTS:
                        sentinel.auto_disconnect_from_network(threat_sample["agent_id"])

                # Shutting down the machine
                if sentinel.config.ACTION.AUTO_SHUTDOWN.ACTIVE:
                    if threat_sample and sample_data["sample_verdict"] in sentinel.config.ACTION.AUTO_SHUTDOWN.VERDICTS:
                        sentinel.auto_shutdown_machine(threat_sample["agent_id"])

            # If sample identified as clean from VMRay
            elif sample_data["sample_verdict"] == VERDICT.CLEAN:
                # If sample marked as threat by SentinelOne and auto update verdict enabled,
                # add a note and update analyst verdict as false positive
                if sentinel.config.THREAT.AUTO_UPDATE_FALSE_POSITIVE_VERDICT.ACTIVE \
                and sample["sample_type"] == SAMPLE_TYPE.THREAT \
                and sample["confidenceLevel"] in sentinel.config.THREAT.AUTO_UPDATE_FALSE_POSITIVE_VERDICT.VERDICTS:
                    sentinel.update_analyst_verdict(sample["id"], ANALYST_VERDICTS.FALSE_POSITIVE)
                    sentinel.create_note(sample["id"], sample_data, sample_vtis={}, sample_iocs={})

    # Removing downloaded files
    for downloaded_evidence in downloaded_samples:
        shutil.rmtree(downloaded_evidence["download_folder_path"], ignore_errors=True)


if __name__ == "__main__":
    from app.lib.SentinelOne import SentinelOne
    from app.lib.VMRay import VMRay
    from app.config.conf import GeneralConfig, SentinelOneConfig, DOWNLOAD_METHODS, VERDICT, ANALYST_VERDICTS
    from app.config.conf import RUNTIME_MODE, SAMPLE_TYPE, MITIGATION_TYPE, COLLECT_METHODS

    if GeneralConfig.RUNTIME_MODE == RUNTIME_MODE.DOCKER:
        while True:
            run()
            log.info("Sleeping %d seconds." % GeneralConfig.TIME_SPAN)
            time.sleep(GeneralConfig.TIME_SPAN)

    elif GeneralConfig.RUNTIME_MODE == RUNTIME_MODE.CLI:
        run()
