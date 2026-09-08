.PHONY: run test demo-data build-multiday train-multiday evaluate-multiday build-holdout train-holdout evaluate-holdout
run:
	.venv/bin/uvicorn backend.main:app --host 127.0.0.1 --port 8000
test:
	.venv/bin/python -m unittest discover -s tests -v
demo-data:
	.venv/bin/python scripts/generate_demo_flows.py
	.venv/bin/python scripts/generate_demo_pcap.py
build-multiday:
	.venv/bin/python -m pipeline.build_partitioned_dataset --plan datasets/cic2018_multiday_split.json --output data/processed-cic2018-multiday
train-multiday:
	.venv/bin/python -m pipeline.train_lstm --data data/processed-cic2018-multiday --output models/cic2018-multiday-lstm --epochs 80 --patience 12
evaluate-multiday:
	.venv/bin/python -m pipeline.evaluate --data data/processed-cic2018-multiday --checkpoint models/cic2018-multiday-lstm/lstm.pt --baseline models/cic2018-multiday-baseline/baseline.joblib --output data/evaluation/cic2018-multiday-with-ctu13.json --cross-data data/processed-ctu13-s11
build-holdout:
	.venv/bin/python -m pipeline.build_partitioned_dataset --plan datasets/cic2018_infiltration_holdout.json --output data/processed-cic2018-infiltration-holdout
train-holdout:
	.venv/bin/python -m pipeline.train_baseline --data data/processed-cic2018-infiltration-holdout --output models/cic2018-infiltration-holdout-baseline
	.venv/bin/python -m pipeline.train_lstm --data data/processed-cic2018-infiltration-holdout --output models/cic2018-infiltration-holdout-gru --architecture gru --epochs 60 --patience 10 --hidden-size 64 --layers 2
evaluate-holdout:
	.venv/bin/python -m pipeline.evaluate --data data/processed-cic2018-infiltration-holdout --checkpoint models/cic2018-infiltration-holdout-gru/lstm.pt --baseline models/cic2018-infiltration-holdout-baseline/baseline.joblib --output models/cic2018-infiltration-holdout-gru/evaluation.json
