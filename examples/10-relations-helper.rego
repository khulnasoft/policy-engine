# This rule uses a relationship that was defined using the
# vulnmap.relation_from_fields helper function. See <relations.rego> for the
# definition of the "aws_s3_bucket.ownership_controls" relation that we use
# below.
package rules.vulnmap_010.tf

import data.vulnmap

buckets := vulnmap.resources("aws_s3_bucket")

# This deny rule captures buckets that have no ownership controls defined.
deny[info] {
  bucket := buckets[_]
  controls := vulnmap.relates(bucket, "aws_s3_bucket.ownership_controls")
  count(controls) < 1
  info := {
    "resource": bucket,
  }
}

# This deny rule captures buckets that have misconfigured ownership controls
deny[info] {
  bucket := buckets[_]
  controls := vulnmap.relates(bucket, "aws_s3_bucket.ownership_controls")
  control := controls[_]
  control.rule[_].object_ownership != "BucketOwnerEnforced"
  info := {
    "primary_resource": bucket,
    "resource": control,
  }
}

resources[info] {
  bucket := buckets[_]
  info := {
    "resource": bucket,
  }
}

resources[info] {
  bucket := buckets[_]
  control := vulnmap.relates(bucket, "aws_s3_bucket.ownership_controls")[_]
  info := {
    "primary_resource": bucket,
    "resource": control,
  }
}
