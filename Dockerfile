#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

FROM python:3-alpine

COPY requirements.txt /netpol-synthesizer/
RUN pip install -r /netpol-synthesizer/requirements.txt

COPY src/ /netpol-synthesizer/src/
COPY baseline-rules/ /netpol-synthesizer/baseline-rules/

RUN addgroup -S netpolgroup && adduser -S netpoluser -G netpolgroup
USER netpoluser

ENTRYPOINT ["python", "/netpol-synthesizer/src/netpol_synth.py"]
