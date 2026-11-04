from scanner.rules import s3


def test_public_bucket_flagged(session):
    c = session.client("s3")
    c.create_bucket(Bucket="open-bucket")
    c.put_bucket_acl(Bucket="open-bucket", ACL="public-read")
    f = s3.public_bucket(session)
    assert [x.resource for x in f] == ["open-bucket"]
    assert f[0].rule_id == "S3-PUBLIC"


def test_private_bucket_not_flagged(session):
    session.client("s3").create_bucket(Bucket="private-bucket")
    assert s3.public_bucket(session) == []


def test_public_acl_with_block_is_not_flagged(session):
    c = session.client("s3")
    c.create_bucket(Bucket="blocked")
    c.put_bucket_acl(Bucket="blocked", ACL="public-read")
    c.put_public_access_block(Bucket="blocked", PublicAccessBlockConfiguration={
        "BlockPublicAcls": True, "IgnorePublicAcls": True,
        "BlockPublicPolicy": True, "RestrictPublicBuckets": True})
    assert s3.public_bucket(session) == []


def test_versioning_off_and_on(session):
    c = session.client("s3")
    c.create_bucket(Bucket="bucket-a")
    c.create_bucket(Bucket="bucket-b")
    c.put_bucket_versioning(Bucket="bucket-b", VersioningConfiguration={"Status": "Enabled"})
    assert [x.resource for x in s3.versioning_off(session)] == ["bucket-a"]


def test_logging_off(session):
    session.client("s3").create_bucket(Bucket="quiet")
    assert [x.rule_id for x in s3.access_logging_off(session)] == ["S3-LOGGING"]
