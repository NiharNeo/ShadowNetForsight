PYTHON ?= .venv-enterprise/bin/python

.PHONY: run test demo-data controlled-lab-pilot workflow-check workflow-full build-multiday train-multiday evaluate-multiday build-holdout train-holdout evaluate-holdout preflight-pcap-acquisition build-pcap-corpus train-pcap-onset evaluate-pcap-onset
run:
	$(PYTHON) -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --workers 1 --ws-max-size 8192 --ws-max-queue 4
test:
	$(PYTHON) -m unittest discover -s tests -v
demo-data:
	$(PYTHON) scripts/generate_demo_flows.py
	$(PYTHON) scripts/generate_demo_pcap.py
controlled-lab-pilot:
	$(PYTHON) scripts/generate_controlled_lab_pcaps.py
workflow-check:
	$(PYTHON) scripts/run_project_workflow.py pilot
workflow-full:
	$(PYTHON) scripts/run_project_workflow.py full
build-multiday:
	$(PYTHON) -m pipeline.build_partitioned_dataset --plan datasets/cic2018_multiday_split.json --output data/processed-cic2018-multiday
train-multiday:
	$(PYTHON) -m pipeline.train_lstm --data data/processed-cic2018-multiday --output models/cic2018-multiday-lstm --epochs 80 --patience 12
evaluate-multiday:
	$(PYTHON) -m pipeline.evaluate --data data/processed-cic2018-multiday --checkpoint models/cic2018-multiday-lstm/lstm.pt --baseline models/cic2018-multiday-baseline/baseline.joblib --output data/evaluation/cic2018-multiday-with-ctu13.json --cross-data data/processed-ctu13-s11
build-holdout:
	$(PYTHON) -m pipeline.build_partitioned_dataset --plan datasets/cic2018_infiltration_holdout.json --output data/processed-cic2018-infiltration-holdout
train-holdout:
	$(PYTHON) -m pipeline.train_baseline --data data/processed-cic2018-infiltration-holdout --output models/cic2018-infiltration-holdout-baseline
	$(PYTHON) -m pipeline.train_lstm --data data/processed-cic2018-infiltration-holdout --output models/cic2018-infiltration-holdout-gru --architecture gru --epochs 60 --patience 10 --hidden-size 64 --layers 2
evaluate-holdout:
	$(PYTHON) -m pipeline.evaluate --data data/processed-cic2018-infiltration-holdout --checkpoint models/cic2018-infiltration-holdout-gru/lstm.pt --baseline models/cic2018-infiltration-holdout-baseline/baseline.joblib --output models/cic2018-infiltration-holdout-gru/evaluation.json
preflight-pcap-acquisition:
	$(PYTHON) scripts/preflight_pcap_acquisition.py
build-pcap-corpus:
	$(PYTHON) -m pipeline.build_pcap_dataset --plan datasets/pcap_training_plan.json --output data/processed-pcap-corpus
train-pcap-onset:
	$(PYTHON) -m pipeline.train_baseline --data data/processed-pcap-corpus --output models/pcap-onset-baseline
	$(PYTHON) -m pipeline.train_lstm --data data/processed-pcap-corpus --output models/pcap-onset-gru --architecture gru --epochs 80 --patience 12 --hidden-size 64 --layers 2 --onset-loss-weight 4
evaluate-pcap-onset:
	$(PYTHON) -m pipeline.evaluate --data data/processed-pcap-corpus --checkpoint models/pcap-onset-gru/lstm.pt --baseline models/pcap-onset-baseline/baseline.joblib --output models/pcap-onset-gru/evaluation.json

.PHONY: production-check
production-check:
	$(PYTHON) scripts/verify_production.py

.PHONY: demo-up demo-stop demo-status
demo-up:
	$(PYTHON) scripts/demo.py up
demo-stop:
	$(PYTHON) scripts/demo.py stop
demo-status:
	$(PYTHON) scripts/demo.py status
