FROM apache/hive:3.1.3

USER root

RUN apt-get update && \
    apt-get install -y netcat curl && \
    rm -rf /var/lib/apt/lists/*

ENV JAVA_HOME=/opt/java/openjdk
ENV HADOOP_VERSION=3.2.0
ENV METASTORE_VERSION=3.0.0

WORKDIR /opt

ENV HADOOP_HOME=/opt/hadoop-${HADOOP_VERSION}
ENV HIVE_HOME=/opt/apache-hive-metastore-${METASTORE_VERSION}-bin

RUN curl -L https://downloads.apache.org/hive/hive-standalone-metastore-${METASTORE_VERSION}/hive-standalone-metastore-${METASTORE_VERSION}-bin.tar.gz | tar zxf - && \
    curl -L https://archive.apache.org/dist/hadoop/common/hadoop-${HADOOP_VERSION}/hadoop-${HADOOP_VERSION}.tar.gz | tar zxf - && \
    curl -L https://dev.mysql.com/get/Downloads/Connector-J/mysql-connector-java-8.0.19.tar.gz | tar zxf - && \
    curl -L --output postgresql-42.4.0.jar https://jdbc.postgresql.org/download/postgresql-42.4.0.jar && \
    curl -L --output hive-exec-${METASTORE_VERSION}.jar https://repo1.maven.org/maven2/org/apache/hive/hive-exec/${METASTORE_VERSION}/hive-exec-${METASTORE_VERSION}.jar && \
    cp mysql-connector-java-8.0.19/mysql-connector-java-8.0.19.jar ${HIVE_HOME}/lib/ && \
    cp postgresql-42.4.0.jar ${HIVE_HOME}/lib/ && \
    cp hive-exec-${METASTORE_VERSION}.jar ${HIVE_HOME}/lib/ && \
    rm -rf mysql-connector-java-8.0.19

COPY scripts/entrypoint.sh /entrypoint.sh

RUN chown -R hive:hive ${HIVE_HOME} /entrypoint.sh && \
    chmod +x /entrypoint.sh

USER hive

EXPOSE 9083
ENTRYPOINT ["/entrypoint.sh"]