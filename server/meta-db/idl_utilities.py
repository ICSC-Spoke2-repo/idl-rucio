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

inaf_server = [ {
        "ip": config.get('server3', 'ip'),
        "port": int(config.get('server3', 'port')), # The config parser gets all the configs as strings, but the port needs to be an integer
        "name": config.get('server3', 'name')
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
        print(f"IDL Dump Failed. ERROR: {error}")
    else:
        print(f"Successfully dumped the IDL table: {res}")

def dump_table_inaf_metadata_to_warehouse(servers: List, credentials: Dict[str, str]):

    field_labels_string_dict = dict()
    field_labels_string_dict["metadataFermi"] = 'CHECKSUM_HDU0,CHECKSUM_HDU1,CHECKSUM_HDU2,CLOCKAPP,CREATOR,DATASUM_HDU0,DATASUM_HDU1,DATASUM_HDU2,DATE,DATE_END,DATE_OBS,DIFRSP0_HDU1,DIFRSP1_HDU1,DIFRSP2_HDU1,DIFRSP3_HDU1,DIFRSP4_HDU1,DSREF1_HDU1,DSTYP1_HDU1,DSTYP2_HDU1,DSUNI1_HDU1,DSUNI2_HDU1,DSVAL1_HDU1,DSVAL2_HDU1,EQUINOX,EXTEND,EXTNAME_HDU1,EXTNAME_HDU2,EXTVER,EXTVER_HDU2,FILENAME,GCOUNT_HDU1,GCOUNT_HDU2,GPS_OUT,HDUCLASS_HDU1,HDUCLASS_HDU2,HDUCLASS1_HDU1,HDUCLASS1_HDU2,HDUCLASS2_HDU1,HDUCLASS2_HDU2,INSTRUME,MJDREFF,MJDREFI,NAXIS_HDU0,NAXIS_HDU1,NAXIS_HDU2,NAXIS1_HDU1,NAXIS1_HDU2,NAXIS2_HDU1,NAXIS2_HDU2,NDIFRSP,NDSKEYS,OBSERVER,ONTIME,ORIGIN,PASS_VER,PCOUNT_HDU1,PCOUNT_HDU2,PROC_VER,RADECSYS,TABLE_NAME,TASSIGN,TELAPSE,TELESCOP,TIMEREF,TIMESYS,TIMEUNIT,TIMEZERO,TSTART,TSTOP,VERSION,LINK'
    field_labels_string_dict["metadataBirales"] = 'COMMENT,TIME_SYSTEM,START_TIME,STOP_TIME,PARTICIPANT_1,PARTICIPANT_2,PARTICIPANT_3,PATH,ANGLE_TYPE,TRANSMIT_BAND,RECEIVE_BAND,TIMETAG_REF,RANGE_UNITS,DATA_QUALITY,LINK'
    field_labels_string_dict["metadataPulsar"] = 'id,storage_path,file_path,file_version,file_name,telescop,date_obs,observer,obs_mode,backend,ra_rad,dec_rad,ra_c,dec_c,equinox,projid_character,url,policy,p_status,update_time,s_point_public_spoint_1,s_point_public_spoint_2,src_name,npol,tbin,nbits,chan_bw,obsfreq,obsbw,scanlen,checksum,checksum_gz,obsdataformat,LINK'
    
    for table_name in ["metadataFermi", "metadataBirales", "metadataPulsar"]:
    
        res = True
        error = None
        
        field_labels_string = field_labels_string_dict[f"{table_name}"]

        res, error = adbc_1liner__dump_table_to_warehouse__wrapper(servers, credentials, table_name, field_labels_string)
        
        if error == True:
            print(f"INAF Dump {table_name} Failed. ERROR: {error}")
        else:
            print(f"Successfully dumped the INAF table {table_name}: {res}")

if __name__ == "__main__":
    dump_table_idl_metadata_to_warehouse(servers=servers, credentials=credentials)
    dump_table_inaf_metadata_to_warehouse(servers=inaf_server, credentials=credentials)