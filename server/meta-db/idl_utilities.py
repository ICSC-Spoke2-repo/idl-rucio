#!/usr/bin/env python3

from adbc.core.adbc import adbc_1liner__dump_table_to_warehouse__wrapper
from typing import List, Dict
import configparser

config = configparser.ConfigParser()
config.read('/etc/config/AyraDB_cluster_credentials.cfg')

# AyraDB cluster INFN coordinates
servers = [ {
        "ip": config.get('server1', 'ip'),
        "port": int(config.get('server1', 'port')), # The config parser gets all the configs as strings, but the port needs to be an integer
        "name": config.get('server1', 'name')
    },
    {
        "ip": config.get('server2', 'ip'),
        "port": int(config.get('server2', 'port')), # The config parser gets all the configs as strings, but the port needs to be an integer
        "name": config.get('server2', 'name')
    }
]

# INFN cluster credentials
credentials = { "username": config.get('credentials', 'username'), "password": config.get('credentials', 'password')}

def dump_table_idl_metadata_to_warehouse(servers: List, credentials: Dict[str, str]):

    table_name = 'metadata'
    field_labels_string = 'IDL_L4_VERS,COMMENT,CREATION_DATE,TIME_SYSTEM,TIMETAG_REF,EPOCH,START_TIME,STOP_TIME,ORIGINATOR,PARTICIPANT_1,PARTICIPANT_2,PARTICIPANT_3,PARTICIPANT_4,PARTICIPANT_5,PARTICIPANT_N,PATH,REFERENCE_FRAME,SENSOR_TYPE,MEAS_TYPE,MEAS_FORMAT_ANGLE_AZEL,MEAS_RANGE_MIN_AZEL_0,MEAS_RANGE_MAX_AZEL_0,MEAS_RANGE_MIN_AZEL_1,MEAS_RANGE_MAX_AZEL_1,MEAS_FORMAT_ANGLE_RADEC,MEAS_RANGE_MIN_RADEC_0,MEAS_RANGE_MAX_RADEC_0,MEAS_RANGE_MIN_RADEC_1,MEAS_RANGE_MAX_RADEC_1,MEAS_FORMAT_ANGLE_XEYN,MEAS_RANGE_MIN_ANGLE_XEYN_0,MEAS_RANGE_MAX_ANGLE_XEYN_0,MEAS_RANGE_MIN_ANGLE_XEYN_1,MEAS_RANGE_MAX_ANGLE_XEYN_1,MEAS_FORMAT_ANGLE_XSYS,MEAS_RANGE_MIN_ANGLE_XSYS_0,MEAS_RANGE_MAX_ANGLE_XSYS_0,MEAS_RANGE_MIN_ANGLE_XSYS_1,MEAS_RANGE_MAX_ANGLE_XSYS_1,MEAS_FORMAT_ORBIT_XYZ,MEAS_XYZ_0,MEAS_XYZ_1,MEAS_XYZ_2,MEAS_FORMAT_ORBIT_KEP,MEAS_ORBIT_KEP_0,MEAS_ORBIT_KEP_1,MEAS_ORBIT_KEP_2,MEAS_ORBIT_KEP_3,MEAS_ORBIT_KEP_4,MEAS_ORBIT_KEP_5,MEAS_FORMAT_ORBIT_COV,MEAS_FORMAT_RF_SAMPLES,MEAS_FORMAT_RF_PC_NO,MEAS_RANGE_MIN_RF_PC_NO_0,MEAS_RANGE_MAX_RF_PC_NO_0,MEAS_FORMAT_RF_CARRIER_POWER,MEAS_RANGE_MIN_RF_CARRIER_POWER_0,MEAS_RANGE_MAX_RF_CARRIER_POWER_0,MEAS_FORMAT_RF_CARRIER_FREQUENCY,MEAS_RANGE_MIN_RF_CARRIER_FREQUENCY_0,MEAS_RANGE_MAX_RF_CARRIER_FREQUENCY_0,MEAS_FORMAT_RF_OBW,MEAS_RANGE_MIN_RF_OBW_0,MEAS_RANGE_MAX_RF_OBW_0,MEAS_FORMAT_RF_DOPPLER_INSTANTANEOUS,MEAS_RANGE_MIN_RF_DOPPLER_INSTANTANEOUS_0,MEAS_RANGE_MAX_RF_DOPPLER_INSTANTANEOUS_0,MEAS_FORMAT_RF_DOPPLER_INTEGRATED,MEAS_RANGE_MIN_RF_DOPPLER_INTEGRATED_0,MEAS_RANGE_MAX_RF_DOPPLER_INTEGRATED_0,MEAS_FORMAT_RF_MODULATION,MEAS_FORMAT_RCS,MEAS_RANGE_MIN_RCS_0,MEAS_RANGE_MAX_RCS_0,MEAS_FORMAT_RANGE,MEAS_RANGE_MIN_RANGE_0,MEAS_RANGE_MAX_RANGE_0,MEAS_FORMAT_PHOTO_MAG,MEAS_RANGE_MIN_PHOTO_MAG_0,MEAS_RANGE_MAX_PHOTO_MAG_0,MEAS_FORMAT_PHOTO_TEMPERATURE,MEAS_RANGE_MIN_PHOTO_TEMPERATURE_0,MEAS_RANGE_MAX_PHOTO_TEMPERATURE_0,MEAS_OTHER_IMAGE,MEAS_RANGE_DESC,MEAS_RANGE_UNIT,DATA_QUALITY,LINK'
    
    res = True
    error = None
    
    res, error = adbc_1liner__dump_table_to_warehouse__wrapper(servers, credentials, table_name, field_labels_string)
    
    if error == True:
        print(f"Dump Failed. ERROR: {error}")
    else:
        print(f"Successfully dumped the table: {res}")

if __name__ == "__main__":
    dump_table_idl_metadata_to_warehouse(servers=servers, credentials=credentials)