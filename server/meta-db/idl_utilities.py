#!/usr/bin/env python3

import logging
import configparser
import argparse
import sys
from typing import List, Dict
from adbc.core.adbc import adbc_1liner__dump_table_to_warehouse__wrapper

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s] %(asctime)s — %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# Load config
config = configparser.ConfigParser()
config.read('/etc/config/AyraDB_cluster_credentials.cfg')

# Cluster definitions
servers = [
    {
        "ip": config.get('server1', 'ip'),
        "port": int(config.get('server1', 'port')),
        "name": config.get('server1', 'name')
    },
    {
        "ip": config.get('server2', 'ip'),
        "port": int(config.get('server2', 'port')),
        "name": config.get('server2', 'name')
    }
]

inaf_server = [
    {
        "ip": config.get('server3', 'ip'),
        "port": int(config.get('server3', 'port')),
        "name": config.get('server3', 'name')
    }
]

credentials = {
    "username": config.get('credentials', 'username'),
    "password": config.get('credentials', 'password')
}


def dump_table(table_name: str, field_labels_string: str, servers: List, credentials: Dict[str, str], tag: str):
    logger.info(f"[{tag}] Dumping table: {table_name}")
    try:
        res, error = adbc_1liner__dump_table_to_warehouse__wrapper(servers, credentials, table_name, field_labels_string)
        if not res:
            logger.error(f"[{tag}] Dump failed for table '{table_name}': {error}")
        else:
            logger.info(f"[{tag}] Dump successful for table '{table_name}'")
    except Exception as e:
        logger.exception(f"[{tag}] Unexpected error while dumping '{table_name}': {e}")


def dump_tasi_metadata():
    table_name = 'metadata'
    field_labels_string = (
        'IDL_L4_VERS,COMMENT,CREATION_DATE,TIME_SYSTEM,TIMETAG_REF,EPOCH,START_TIME,STOP_TIME,ORIGINATOR,'
        'PARTICIPANT_1,PARTICIPANT_2,PARTICIPANT_3,PARTICIPANT_4,PARTICIPANT_5,PARTICIPANT_N,PATH,REFERENCE_FRAME,'
        'SENSOR_TYPE,MEAS_TYPE,MEAS_FORMAT_ANGLE_AZEL,MEAS_RANGE_MIN_AZEL_0,MEAS_RANGE_MAX_AZEL_0,MEAS_RANGE_MIN_AZEL_1,'
        'MEAS_RANGE_MAX_AZEL_1,MEAS_FORMAT_ANGLE_RADEC,MEAS_RANGE_MIN_RADEC_0,MEAS_RANGE_MAX_RADEC_0,MEAS_RANGE_MIN_RADEC_1,'
        'MEAS_RANGE_MAX_RADEC_1,MEAS_FORMAT_ANGLE_XEYN,MEAS_RANGE_MIN_ANGLE_XEYN_0,MEAS_RANGE_MAX_ANGLE_XEYN_0,'
        'MEAS_RANGE_MIN_ANGLE_XEYN_1,MEAS_RANGE_MAX_ANGLE_XEYN_1,MEAS_FORMAT_ANGLE_XSYS,MEAS_RANGE_MIN_ANGLE_XSYS_0,'
        'MEAS_RANGE_MAX_ANGLE_XSYS_0,MEAS_RANGE_MIN_ANGLE_XSYS_1,MEAS_RANGE_MAX_ANGLE_XSYS_1,MEAS_FORMAT_ORBIT_XYZ,'
        'MEAS_XYZ_0,MEAS_XYZ_1,MEAS_XYZ_2,MEAS_FORMAT_ORBIT_KEP,MEAS_ORBIT_KEP_0,MEAS_ORBIT_KEP_1,MEAS_ORBIT_KEP_2,'
        'MEAS_ORBIT_KEP_3,MEAS_ORBIT_KEP_4,MEAS_ORBIT_KEP_5,MEAS_FORMAT_ORBIT_COV,MEAS_FORMAT_RF_SAMPLES,MEAS_FORMAT_RF_PC_NO,'
        'MEAS_RANGE_MIN_RF_PC_NO_0,MEAS_RANGE_MAX_RF_PC_NO_0,MEAS_FORMAT_RF_CARRIER_POWER,MEAS_RANGE_MIN_RF_CARRIER_POWER_0,'
        'MEAS_RANGE_MAX_RF_CARRIER_POWER_0,MEAS_FORMAT_RF_CARRIER_FREQUENCY,MEAS_RANGE_MIN_RF_CARRIER_FREQUENCY_0,'
        'MEAS_RANGE_MAX_RF_CARRIER_FREQUENCY_0,MEAS_FORMAT_RF_OBW,MEAS_RANGE_MIN_RF_OBW_0,MEAS_RANGE_MAX_RF_OBW_0,'
        'MEAS_FORMAT_RF_DOPPLER_INSTANTANEOUS,MEAS_RANGE_MIN_RF_DOPPLER_INSTANTANEOUS_0,MEAS_RANGE_MAX_RF_DOPPLER_INSTANTANEOUS_0,'
        'MEAS_FORMAT_RF_DOPPLER_INTEGRATED,MEAS_RANGE_MIN_RF_DOPPLER_INTEGRATED_0,MEAS_RANGE_MAX_RF_DOPPLER_INTEGRATED_0,'
        'MEAS_FORMAT_RF_MODULATION,MEAS_FORMAT_RCS,MEAS_RANGE_MIN_RCS_0,MEAS_RANGE_MAX_RCS_0,MEAS_FORMAT_RANGE,'
        'MEAS_RANGE_MIN_RANGE_0,MEAS_RANGE_MAX_RANGE_0,MEAS_FORMAT_PHOTO_MAG,MEAS_RANGE_MIN_PHOTO_MAG_0,MEAS_RANGE_MAX_PHOTO_MAG_0,'
        'MEAS_FORMAT_PHOTO_TEMPERATURE,MEAS_RANGE_MIN_PHOTO_TEMPERATURE_0,MEAS_RANGE_MAX_PHOTO_TEMPERATURE_0,MEAS_OTHER_IMAGE,'
        'MEAS_RANGE_DESC,MEAS_RANGE_UNIT,DATA_QUALITY,LINK'
    )
    dump_table(table_name, field_labels_string, servers, credentials, "TASI")


def dump_inaf_metadata():
    table_fields = {
        "metadataFermi": 'DSVAL1_HDU1,MJDREFI,DSTYP2_HDU1,TIMEZERO,OBSERVER,ORIGIN,TIMESYS,EXTEND,CHECKSUM_HDU0,TSTOP,'
                        'CHECKSUM_HDU1,DSVAL2_HDU1,DATE_END,INSTRUME,CHECKSUM_HDU2,DSTYP1_HDU1,TIMEUNIT,DATASUM_HDU0,'
                        'DATASUM_HDU2,CLOCKAPP,DSREF1_HDU1,DATE_OBS,EQUINOX,VERSION,HDUCLASS_HDU1,DATASUM_HDU1,CREATOR,'
                        'DIFRSP2_HDU1,RADECSYS,EXTNAME_HDU2,TIMEREF,MJDREFF,DIFRSP4_HDU1,DIFRSP0_HDU1,DATE,DIFRSP3_HDU1,'
                        'EXTNAME_HDU1,GPS_OUT,DIFRSP1_HDU1,HDUCLASS_HDU2,TSTART,DSUNI1_HDU1,TELESCOP,DSUNI2_HDU1,FILENAME,'
                        'WEEK,TABLE_NAME,CHECKSUM,UPDATE_TIME,RSE,LINK',
        "metadataBirales": 'COMMENT,TIME_SYSTEM,START_TIME,STOP_TIME,PARTICIPANT_1,PARTICIPANT_2,PARTICIPANT_3,PATH,'
                           'ANGLE_TYPE,TRANSMIT_BAND,RECEIVE_BAND,TIMETAG_REF,RANGE_UNITS,DATA_QUALITY,LINK',
        "metadataPulsar": 'BACKEND,DATE_OBS,DEC_C,EQUINOX,OBS_MODE,OBSERVER,PROJID_CHARACTER,RA_C,TELESCOP,CHAN_BW,NBITS,'
                          'NPOL,SRC_NAME,TBIN,OBSBW,OBSFREQ,SCANLEN,OBSDATAFORMAT,DEC_RAD,FILE_NAME,POLICY,RA_RAD,'
                          'UPDATE_TIME,S_POINT_PUBLIC_SPOINT_1,S_POINT_PUBLIC_SPOINT_2,FILE_VERSION,CHECKSUM,RSE,LINK'
    }

    for table, fields in table_fields.items():
        dump_table(table, fields, inaf_server, credentials, "INAF")


def main():
    parser = argparse.ArgumentParser(
        description='Dump metadata tables to warehouse with logging and config support.'
    )
    parser.add_argument('--tasi', action='store_true', help='Dump TASI metadata table')
    parser.add_argument('--inaf', action='store_true', help='Dump INAF metadata tables')
    parser.add_argument('--all', action='store_true', help='Dump all tables (TASI + INAF)')

    args = parser.parse_args()

    if not any([args.tasi, args.inaf, args.all]):
        parser.print_help()
        sys.exit(1)

    if args.all or args.tasi:
        dump_tasi_metadata()
    if args.all or args.inaf:
        dump_inaf_metadata()


if __name__ == "__main__":
    main()