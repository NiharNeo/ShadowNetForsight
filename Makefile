.PHONY: run test demo-data build-multiday train-multiday evaluate-multiday
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
