FROM opennms/horizon:bleeding

USER root

# Copy our customized OpenNMS config
COPY opennms-config/datacollection/cisco.xml \
     /opt/opennms/etc/datacollection/cisco.xml

COPY opennms-config/snmp-graph.properties.d/cisco-cpu-cpm.graph.properties \
     /opt/opennms/etc/snmp-graph.properties.d/cisco-cpu-cpm.graph.properties

# Ensure correct ownership
RUN chown opennms:opennms \
    /opt/opennms/etc/datacollection/cisco.xml \
    /opt/opennms/etc/snmp-graph.properties.d/cisco-cpu-cpm.graph.properties

USER opennms
