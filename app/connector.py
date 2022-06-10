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

    # Dict of evidences which need to be downloaded from SentinelOne
    download_evidences = {}

    # Retrieving evidences from SentinelOne
    evidences = sentinel.get_evidences_from_threats()

    # Checking hash values in VMRay database, if evidence is found on VMRay no need to submit again
    for sha1 in evidences:
        sample = vmray.get_sample(sha1)
        evidences[sha1]["sample"] = sample
        if sample is not None:
            # if evidence found on VMRay we need to store sample metadata in Evidence object
            found_evidences[sha1] = evidences[sha1]
        else:
            download_evidences[sha1] = evidences[sha1]

    log.info("%d evidences found on VMRay database" % len(found_evidences))
    log.info("%d evidences need to be downloaded and submitted" % len(download_evidences))

    # Fetch request to generate evidence files' download link from SentinelOne
    fetched_evidences = sentinel.fetch_request_evidence_file(download_evidences)
    # Download evidence files from SentinelOne
    downloaded_evidences = sentinel.download_samples(fetched_evidences)
    log.info("%d evidence file downloaded successfully" % len(downloaded_evidences))

    # Dict of processes file which found on VMRay database
    found_processes = {}

    # Dict of processes which need to be downloaded from SentinelOne
    download_processes = {}

    # Retrieving process file from SentinelOne
    processes = sentinel.get_process_from_dv()

    # Checking hash values in VMRay database, if process file is found on VMRay no need to submit again
    for sha1 in processes:
        sample = vmray.get_sample(sha1)
        processes[sha1]["sample"] = sample
        if sample is not None:
            # if process file found on VMRay we need store sample metadata in Process object
            found_processes[sha1] = processes[sha1]
        else:
            download_processes[sha1] = processes[sha1]

    log.info("%d process file found on VMRay database" % len(found_processes))
    log.info("%d process file need to be downloaded and submitted" % len(download_processes))

    # Fetch request to generate process files download link from SentinelOne
    fetched_processes = sentinel.fetch_request_process_file(download_processes)
    # Download process files from SentinelOne
    downloaded_processes = sentinel.download_samples(fetched_processes)
    log.info("%d process file downloaded successfully" % len(downloaded_processes))

    # Merge found and downloaded dictionaries
    found_samples = {**found_processes, **found_evidences}
    downloaded_samples = downloaded_evidences + downloaded_processes

    # Retrieving indicators from SentinelOne to check duplicates
    old_indicators = sentinel.get_indicators()

    # Retrieving indicators from VMRay Analyzer for found evidences
    for sha1 in found_samples:
        sample = found_samples[sha1]
        sample_data = vmray.parse_sample_data(sample["sample"])

        # If sample identified as suspicious or malicious
        # we need to extract indicator values and import them to SentinelOne
        if sample_data["sample_verdict"] in GeneralConfig.SELECTED_VERDICTS:
            # Retrieving and parsing indicators
            sample_iocs = vmray.get_sample_iocs(sample_data)
            ioc_data = vmray.parse_sample_iocs(sample_iocs)

            # Creating SentinelOne IOC objects for IOC values
            indicator_objects = sentinel.create_indicator_objects(ioc_data, old_indicators, sample_data)

            # Submitting new indicators to SentinelOne
            sentinel.submit_indicators(indicator_objects)

            # If sample marked as threat by SentinelOne, add a note with vtis and sample metadata
            if sample["sample_type"] == SAMPLE_TYPE.THREAT:
                # Retrieving and parsing sample vtis from VMRay Analyzer
                vti_data = vmray.get_sample_vtis(sample_data["sample_id"])
                sample_vtis = vmray.parse_sample_vtis(vti_data)
                sentinel.create_note(sample["id"], sample_data, sample_vtis)

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
                # Retrieving and parsing indicators
                sample_iocs = vmray.get_sample_iocs(sample_data)
                ioc_data = vmray.parse_sample_iocs(sample_iocs)

                # Creating SentinelOne IOC objects for IOC values
                indicator_objects = sentinel.create_indicator_objects(ioc_data, old_indicators, sample_data)

                # Submitting new indicators to SentinelOne
                sentinel.submit_indicators(indicator_objects)

                # Getting sample object from evidence list or process list
                threat_sample = None
                if sample_data["sample_sha1hash"] in evidences:
                    threat_sample = evidences[sample_data["sample_sha1hash"]]
                elif sample_data["sample_sha1hash"] in processes:
                    threat_sample = processes[sample_data["sample_sha1hash"]]

                # if SentinelOne has this threat add a note with vtis and sample metadata
                if sample_data["sample_sha1hash"] in evidences:
                    # Retrieving and parsing sample vtis from VMRay Analyzer
                    vti_data = vmray.get_sample_vtis(sample_data["sample_id"])
                    sample_vtis = vmray.parse_sample_vtis(vti_data)
                    sentinel.create_note(threat_sample["id"], sample_data, sample_vtis)

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
                    if sample_data["sample_sha1hash"] in evidences and sample_data["sample_verdict"] in sentinel.config.ACTION.AUTO_KILL.VERDICTS:
                        sentinel.auto_mitigate_threat(threat_sample["id"], threat_sample['agent_id'], MITIGATION_TYPE.KILL)

                # Mitigating threat with Quarantine File
                if sentinel.config.ACTION.AUTO_QUARANTINE.ACTIVE:
                    if sample_data["sample_sha1hash"] in evidences and sample_data["sample_verdict"] in sentinel.config.ACTION.AUTO_QUARANTINE.VERDICTS:
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

    # Removing downloaded files
    for downloaded_evidence in downloaded_samples:
        shutil.rmtree(downloaded_evidence["download_folder_path"], ignore_errors=True)


if __name__ == "__main__":
    from app.lib.SentinelOne import SentinelOne
    from app.lib.VMRay import VMRay
    from app.config.conf import GeneralConfig, SentinelOneConfig
    from app.config.conf import RUNTIME_MODE, SAMPLE_TYPE, MITIGATION_TYPE

    if GeneralConfig.RUNTIME_MODE == RUNTIME_MODE.DOCKER:
        while True:
            run()
            log.info("Sleeping %d seconds." % GeneralConfig.TIME_SPAN)
            time.sleep(GeneralConfig.TIME_SPAN)

    elif GeneralConfig.RUNTIME_MODE == RUNTIME_MODE.CLI:
        run()
