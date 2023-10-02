# Advanced rules are rules that can inspect multiple resources at once.
package rules.khulnasoft_003.tf

import data.khulnasoft

# `resource_type` can be omitted.  If it is present, it must be set to
# `MULTIPLE` for advanced rules.
# resource_type = "MULTIPLE"

# Advanced rules can list resources of a specific type using
# `khulnasoft.resources(resource_type)`.
#
# This function returns an array of resources of the requested type.
buckets = khulnasoft.resources("aws_s3_bucket")

has_bucket_name(bucket) {
	is_string(bucket.bucket)
	contains(bucket.bucket, "bucket")
}

has_bucket_name(bucket) {
	is_string(bucket.bucket_prefix)
	contains(bucket.bucket_prefix, "bucket")
}

# Advanced rules must contain a `deny` set.  If the deny is associated with a
# specific object, they should set the `resource` field in the info object.
deny[info] {
	bucket := buckets[_]
	has_bucket_name(bucket)
	info := {
		"message": "Bucket names should not contain the word bucket, it's implied",
		"resource": bucket,
	}
}
