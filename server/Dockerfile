FROM rucio/rucio-server:release-35.1.0

# Edit to the kwargs passed in some of the replica.py methods
COPY ./server/replica.py /usr/local/lib/python3.9/site-packages/rucio/gateway/replica.py

# Client for AyraDB connection and communications
COPY ./server/adbc-1.0.1-py3-none-any.whl /usr/local/lib/python3.9/site-packages/adbc-1.0.1-py3-none-any.whl
RUN pip install /usr/local/lib/python3.9/site-packages/adbc-1.0.1-py3-none-any.whl
RUN pip install psutil