# TECHTREK demo narration

We are TECHTREK, team 140638. ShadowNet ForeSight is a research prototype for temporal network forecasting.

The dashboard opens without prefilled predictions. We upload a synthetic three-minute PCAP and process its packets in five-second windows. The signal stream shows measured packet activity; the network graph shows observed connections, not predicted attack paths.

After one minute of capture history, the trained checkpoint produces forecasts at five, ten and fifteen seconds. Feature attributions explain which inputs influence these scores. This fixture falls outside the training distribution, so scores remain exploratory and operational alerts are disabled.

The benign fixture is also rejected. These files prove that the pipeline executes, not that the detector is accurate. The Model evidence view reports the held-out evaluation and generalization limitations. Our compatibility report includes file hashes and every model-ready output for reproducibility.

The application runs in Docker with authenticated uploads and persistent audit history. We have also trained packet-aligned detectors on real labelled captures. Those offline results are shown separately: high aggregate detection did not pass the per-capture false-positive screen, so those models were not deployed. Our next milestone is stronger benign-traffic coverage and fresh independent validation.
