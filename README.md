# AWS CloudFront log expire

Processes an S3 bucket configured as a [CloudFront](https://aws.amazon.com/cloudfront/) distribution access log target - removing all access log objects prior to a specified expiry date or days.

- For safety, will only consider objects for deletion that meet the CloudFront access log naming format.
- By default will only _simulate_ the processing of logs before actual removal from S3 (providing the `--commit` argument will enable actual deletes).
- Can optionally display script processing output back to the users terminal.
- Requires [Boto 2](https://github.com/boto/boto).
- AWS credentials expected to be provided either via shell environment variables or the usual places [Boto will check](https://boto.cloudhackers.com/en/latest/boto_config_tut.html).

## Usage

```
usage: cloudfrontlogexpire.py [-h] --s3-bucket-name NAME
                              [--s3-bucket-log-prefix PREFIX]
                              [--expire-before YYYY-MM-DD]
                              [--expire-days DAY_COUNT] [--progress]
                              [--commit]

Remove AWS CloudFront access log archives from an S3 bucket before a given
date or number of expiry days.

optional arguments:
  -h, --help            show this help message and exit
  --s3-bucket-name NAME
                        S3 bucket holding CloudFront access log archives
  --s3-bucket-log-prefix PREFIX
                        S3 bucket path prefix to access log archives
  --expire-before YYYY-MM-DD
                        expire log archives before given date
  --expire-days DAY_COUNT
                        expire log archives older than X number of days
  --progress            display progress of access log archive processing
  --commit              delete access log archives, otherwise simulation only
```

Notes:

- Must specify one of `--expire-before` or `--expire-days` - not both.
- Script will *never* delete bucket objects unless the `--commit` argument is provided.
