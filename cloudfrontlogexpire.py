#!/usr/bin/env python

import argparse
import calendar
import datetime
import re
import sys
import boto.s3.connection as s3

CLOUDTRAIL_ACCESS_LOG_REGEXP = re.compile(
    r"(^|\/)[A-Z0-9]{13,14}\.[0-9]{4}-[0-1][0-9]-[0-3][0-9]-[0-9]{2}\.[a-f0-9]{8}\.gz$"
)
BOTO_S3_OBJECT_LAST_MODIFIED_REGEXP = re.compile(r"^([0-9]{4})-([0-9]{2})-([0-9]{2})T")
S3_OBJECT_DELETE_QUEUE_LIMIT = 1000


def exit_error(message):
    sys.stderr.write("Error: {0}\n".format(message))
    sys.exit(1)


def read_arguments():
    # create parser
    parser = argparse.ArgumentParser(
        description="Remove AWS CloudFront access log archives from an "
        "S3 bucket before a given date or number of expiry days"
    )

    parser.add_argument(
        "--s3-bucket-name",
        help="S3 bucket holding CloudFront access log archives",
        metavar="NAME",
        required=True,
    )

    parser.add_argument(
        "--s3-bucket-log-prefix",
        help="S3 bucket path prefix to access log archives",
        metavar="PREFIX",
    )

    parser.add_argument(
        "--expire-before",
        help="expire log archives before given date",
        metavar="YYYY-MM-DD",
    )

    parser.add_argument(
        "--expire-days",
        help="expire log archives older than X number of days",
        metavar="DAY_COUNT",
    )

    parser.add_argument(
        "--progress",
        action="store_true",
        help="display progress of access log archive processing",
    )

    parser.add_argument(
        "--commit",
        action="store_true",
        help="delete access log archives, otherwise simulation only",
    )

    args_list = parser.parse_args()

    # validate source S3 bucket name
    if not re.search(r"^[a-z0-9][a-z0-9-.]{1,61}[a-z0-9]$", args_list.s3_bucket_name):
        exit_error(
            "Invalid source S3 bucket name [{0}]".format(args_list.s3_bucket_name)
        )

    # validate source bucket log prefix
    s3_bucket_log_prefix_path = None
    if args_list.s3_bucket_log_prefix is not None:
        if not re.search(r"^[a-z0-9-./]+$", args_list.s3_bucket_log_prefix):
            exit_error(
                "Invalid S3 bucket path log prefix [{0}]".format(
                    args_list.s3_bucket_log_prefix
                )
            )

        # validated - remove leading/trailing forward slashes and add final trailing slash
        s3_bucket_log_prefix_path = args_list.s3_bucket_log_prefix.strip("/") + "/"

    # determine access log expiry criteria
    if (args_list.expire_before is not None) and (args_list.expire_days is not None):
        exit_error("Please specify only one of expire before date / expire days")

    access_log_expire_before = None
    if args_list.expire_before is not None:
        # validate format of given expiry date
        expire_date_match = re.search(
            r"^([0-9]{4})-([0-9]{1,2})-([0-9]{1,2})$", args_list.expire_before
        )
        if not expire_date_match:
            exit_error("Invalid format for expire before date, expected YYYY-MM-DD")

        # fetch date parts
        expire_date_year = int(expire_date_match.group(1))
        expire_date_month = int(expire_date_match.group(2))
        expire_date_day = int(expire_date_match.group(3))

        # year and month in range?
        if not (2006 <= expire_date_year <= 2048):
            exit_error(
                "Invalid year for expire before date [{0}]".format(
                    expire_date_match.group(1)
                )
            )

        if not (1 <= expire_date_month <= 12):
            exit_error(
                "Invalid month for expire before date [{0}]".format(
                    expire_date_match.group(2)
                )
            )

        # valid day of month for year/month given?
        if not (
            1
            <= expire_date_day
            <= calendar.monthrange(expire_date_year, expire_date_month)[1]
        ):
            exit_error(
                "Invalid day of month for expire before date [{0}]".format(
                    expire_date_match.group(3)
                )
            )

        # build expire before date object
        access_log_expire_before = datetime.date(
            expire_date_year, expire_date_month, expire_date_day
        )

    elif args_list.expire_days is not None:
        # ensure day count given as a positive integer
        if not re.search(r"^[1-9][0-9]{0,20}$", args_list.expire_days):
            exit_error(
                "Invalid value for expire days [{0}]".format(args_list.expire_days)
            )

        # calculate expiry date from current date
        access_log_expire_before = datetime.date.today() - datetime.timedelta(
            days=int(args_list.expire_days)
        )

    else:
        # didn't give one of the required expiry criteria types
        exit_error(
            "Must specify log archive expiry as one of --expire-before or --expire-days"
        )

    # return arguments
    return (
        args_list.s3_bucket_name,
        s3_bucket_log_prefix_path,
        access_log_expire_before,
        args_list.progress,
        args_list.commit,
    )


def process_bucket(
    log_bucket,
    s3_bucket_log_prefix_path,
    access_log_expire_before,
    show_progress,
    delete_expired,
):
    # init counters/lists
    archive_seen_count = 0
    archive_delete_count = 0
    delete_object_key_queue = []
    bucket_list_prefix = (
        "" if (not s3_bucket_log_prefix_path) else s3_bucket_log_prefix_path
    )

    def queue_object_delete(object_key=None, force_delete=False):
        # add bucket object to delete queue
        if object_key:
            delete_object_key_queue.append(object_key)

        # is queue at limit?
        queue_length = len(delete_object_key_queue)

        if (force_delete and queue_length) or (
            queue_length >= S3_OBJECT_DELETE_QUEUE_LIMIT
        ):
            # send delete operation to S3 bucket then truncate queue
            log_bucket.delete_keys(delete_object_key_queue, quiet=True)
            del delete_object_key_queue[:]

    # iterate over bucket objects (keys) looking for CloudFront access log archive matches
    for bucket_object_item in log_bucket.list(prefix=bucket_list_prefix):
        object_item_key = bucket_object_item.key

        if not CLOUDTRAIL_ACCESS_LOG_REGEXP.search(object_item_key):
            # S3 object is not a CloudTrail access log archive to be considered
            continue

        # extract last modified date
        access_log_last_modified = get_boto_s3_object_last_modified_date(
            bucket_object_item.last_modified
        )
        if not access_log_last_modified:
            # unable to extract date from object
            continue

        # modified date of access log before expire cutoff?
        delete_log = access_log_last_modified < access_log_expire_before
        archive_seen_count += 1

        # display delete/keep object decision
        if show_progress:
            print(
                "{0} - {1}{2}".format(
                    object_item_key,
                    "DELETE" if (delete_log) else "KEEP",
                    "" if (delete_expired) else " (DRY RUN)",
                )
            )

        # delete access log object from S3
        if delete_log:
            archive_delete_count += 1

            if delete_expired:
                # delete the access log object (not dry-run)
                queue_object_delete(object_item_key)

    # final call to delete any remaining queue items
    queue_object_delete(force_delete=True)

    # return counters
    return (archive_seen_count, archive_delete_count)


def get_boto_s3_object_last_modified_date(boto_datetime):
    datetime_match = BOTO_S3_OBJECT_LAST_MODIFIED_REGEXP.search(boto_datetime)

    if not datetime_match:
        # unable to extract date from given timestamp
        return None

    # create date object (don't care about time) and return
    return datetime.date(
        int(datetime_match.group(1)),
        int(datetime_match.group(2)),
        int(datetime_match.group(3)),
    )


def main():
    # fetch CLI arguments
    (
        s3_bucket_name,
        s3_bucket_log_prefix_path,
        access_log_expire_before,
        show_progress,
        delete_expired,
    ) = read_arguments()

    # create connection to S3 bucket
    s3_connection = s3.S3Connection()
    log_bucket = s3_connection.lookup(s3_bucket_name)

    # does bucket exist?
    if log_bucket is None:
        exit_error(
            "Unable to open requested S3 bucket - does not exist or insufficient permissions [{0}]".format(
                s3_bucket_name
            )
        )

    # print details of where we are scanning
    print("Processing S3 bucket [{0}]".format(s3_bucket_name))

    if s3_bucket_log_prefix_path:
        print("Log prefix path [{0}]".format(s3_bucket_log_prefix_path))

    print(
        "Deleting logs prior to [{0}]\n".format(
            access_log_expire_before.strftime("%Y-%m-%d")
        )
    )

    # process bucket
    archive_seen_count, archive_delete_count = process_bucket(
        log_bucket,
        s3_bucket_log_prefix_path,
        access_log_expire_before,
        show_progress,
        delete_expired,
    )

    # write summary details
    print("\nTotal archive count [{0}]".format(archive_seen_count))

    print(
        "Archives deleted [{0}]{1}".format(
            archive_delete_count, "" if (delete_expired) else " (DRY RUN)"
        )
    )

    print("Remaining [{0}]".format(archive_seen_count - archive_delete_count))


if __name__ == "__main__":
    main()
