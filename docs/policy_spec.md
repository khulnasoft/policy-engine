# Policies specification

This document describes the contract and API for policies that run in the policy engine.

- [Policies specification](#policies-specification)
  - [Conventions in this document](#conventions-in-this-document)
    - [Policy vs. rule](#policy-vs-rule)
  - [Policy requirements](#policy-requirements)
    - [`input_type`](#input_type)
    - [`deny[info]`](#denyinfo)
      - [`info` object properties](#info-object-properties)
        - [`primary_resource` vs `resource`](#primary_resource-vs-resource)
  - [Optional rules](#optional-rules)
    - [`resource_type`](#resource_type)
    - [`metadata`](#metadata)
      - [Supported fields](#supported-fields)
      - [Remediation](#remediation)
    - [`resources[info]`](#resourcesinfo)
      - [`info` object properties](#info-object-properties-1)
      - [Correlation IDs](#correlation-ids)
      - [Graph](#graph)
      - [Examples](#examples)
  - [Policy archetypes](#policy-archetypes)
    - [Single-resource policy](#single-resource-policy)
      - [Single-resource policy examples](#single-resource-policy-examples)
    - [Multi-resource policy](#multi-resource-policy)
      - [Multi-resource policy examples](#multi-resource-policy-examples)
    - [Missing-resource policy](#missing-resource-policy)
      - [Missing-resource policy examples](#missing-resource-policy-examples)
  - [The `vulnmap` API](#the-vulnmap-api)
    - [`vulnmap.resources(<resource type>)`](#vulnmapresourcesresource-type)
      - [Example `vulnmap.resources` call and output](#example-vulnmapresources-call-and-output)
    - [`vulnmap.query(<query>)`](#vulnmapqueryquery)
    - [`vulnmap.relates(<resource>, <relation name>)`](#vulnmaprelatesresource-relation-name)
      - [`vulnmap.back_relates(<relation name>, <resource>)`](#vulnmapback_relatesrelation-name-resource)
      - [`vulnmap.relates_with(<resource>, <relation name>)`](#vulnmaprelates_withresource-relation-name)
      - [`vulnmap.back_relates_with(<relation name>, <resource>)`](#vulnmapback_relates_withrelation-name-resource)
    - [`vulnmap.input_resource_types`](#vulnmapinput_resource_types)
      - [Example vulnmap.input\_resource\_types usage](#example-vulnmapinput_resource_types-usage)
    - [`vulnmap.input_type`](#vulnmapinput_type)
      - [Example `vulnmap.input_type` usage](#example-vulnmapinput_type-usage)
    - [`vulnmap.terraform.resource_provider_version_constraint(<resource>, <constraint>)`](#vulnmapterraformresource_provider_version_constraintresource-constraint)
  - [Resource relations specification](#resource-relations-specification)
  - [Types reference](#types-reference)
    - [State object](#state-object)
    - [Resource objects](#resource-objects)
      - [Obtaining resource objects](#obtaining-resource-objects)
    - [Attribute paths](#attribute-paths)

## Conventions in this document

### Policy vs. rule

This document uses the term "policy" to refer to an OPA package in one or more rego
files that the policy engine queries in order to evaluate some input. This is mainly
done to disambiguate "rules" in the Open Policy Agent terminology (which is used
extensively throughout this document) from what Vulnmap refers to as a rule elsewhere.

## Policy requirements

1. Policies must be in a sub-package of `rules`. Examples of valid package declarations:
    - `package rules.my_rule`
    - `package rules.vulnmap_007.tf`
    
2. Policies must have an `input_type` set. 

3. Policies must contain a `deny[info]` "judgement rule", where `info` is an object
   (which is described in the next section). It's assumed that the `deny[info]` rule
   is written to match failing resources or conditions.
    * The required fields in the `info` object will depend on which
      [archetype](#policy-archetypes) the policy conforms to.

### `input_type`

By default, each policy will be evaluated for all input types. The `input_type` rule can
be used to limit which input types the policy is evaluated for. It is best practice to specify this rule in all policies. 

There is a hierarchy to input types that enables policy authors to still write a single policy 
that applies to multiple types.
The current list of valid values for this rule are:

* `tf_hcl` (Terraform HCL)
* `tf_plan` (Terraform plan file)
* `tf_state` (Terraform state file)
* `cloud_scan` (State produced by Vulnmap Cloud)
* `cfn` (Cloudformation template)
* `k8s` (Kubernetes manifest)
* `arm` (Azure ARM template)
* `tf` (an aggregate type that includes: `tf_hcl`, `tf_plan`, `tf_state`, and `cloud_scan`)

### `deny[info]`

#### `info` object properties

This table lists each supported property of the `info` object along with which policy
archetypes would use it.

| Field              |  Type  | Description                                                                        | Single-resource | Multi-resource | Missing-resource |
| :----------------- | :----: | :--------------------------------------------------------------------------------- | :-------------: | :------------: | :--------------: |
| `primary_resource` | object | The primary [resource object](#resource-objects) associated with the `deny` result |                 |       ✓        |                  |
| `resource`         | object | The [resource object](#resource-objects) that caused the `deny` result             |                 |       ✓        |                  |
| `message`          | string | A message that is specific to this result                                          |        ✓        |       ✓        |        ✓         |
| `resource_type`    | string | The type of resource that is missing                                               |                 |                |        ✓         |
| `remediation`      | string | Remediation steps for the issue identified by this `deny` rule                     |        ✓        |       ✓        |        ✓         |
| `severity`         | string | The severity of the issue identified by this `deny` rule                           |        ✓        |       ✓        |        ✓         |
| `attributes`       | array  | An array of [attribute paths](#attribute-paths)                                    |        ✓        |       ✓        |                  |
| `correlation`      | string | A manually-specified [correlation ID](#correlation-ids)                            |                 |       ✓        |        ✓         |
| `graph`            | object | A list of labeled edges that relate two resources, see [Graph](#graph)             |                 |       ✓        |                  |

##### `primary_resource` vs `resource`

The `resource` attribute can either communicate _what_ is invalid or _why_
another resource is invalid. `attributes` always communicate the reason for the
result and are always assumed to belong to `resource`.

For example:

```open-policy-agent
deny[info] {
  # ...
  info := {
    "resource": some_s3_bucket,
    "attributes": [["some", "attribute", "path"]],
  }
}
```

Can be interpreted as saying:

> `some_s3_bucket` is invalid, because of its attribute `some.attribute.path`.

Whereas in another example where both `primary_resource` and `resource` are
specified:

```open-policy-agent
deny[info] {
  # ...
  info := {
    "primary_resource": some_s3_bucket,
    "resource": an_s3_bucket_policy,
    "attributes": [["policy", "statement", "path"]],
  }
}
```

Can be interpreted as saying:

> `some_s3_bucket` is invalid, because of the `policy.statement.path` attribute
> of `an_s3_bucket_policy`.

So, when only `resource` is specified, it is also assumed to be the primary
resource of that result. Alternatively, the primary resource can be explicitly
specified with the `primary_resource` attribute. If you only specify the
`primary_resource` attribute and not the `resource` attribute, it has the same
effect as only setting the `resource` attribute.

## Optional rules

### `resource_type`

When `resource_type` is set to `MULTIPLE`, the `input` document will be set to the
[State object](#state-object) that is currently being processed by the engine. 

When `resource_type` is set to a specific resource type (e.g. `aws_s3_bucket`), the
policy engine will set the `input` document to the `attributes` object of a single
resource state. 

When `resource_type` is unspecified, it defaults to `MULTIPLE`.

Examples:

```open-policy-agent
resource_type := "MULTIPLE"
```

```open-policy-agent
resource_type := "aws_s3_bucket"
```

### `metadata`

The `metadata` rule defines static metadata associated with the policy. See the
[`deny` rule section](#denyinfo) for result-specific metadata.

#### Supported fields

**NOTE** that `policy-engine` by itself does not enforce any restrictions on
metadata fields apart from their data type.  Custom, extra fields can be added
but these will not be present in the `policy-engine` output.  The descriptions
below are mostly intended to clarify the intent of each field.

| Field           |  Type  | Description                                                                                                      |
| :-------------- | :----: | :--------------------------------------------------------------------------------------------------------------- |
| `id`            | string | A short identifier for the policy. The same ID can be shared across different implementations of the same policy |
| `title`         | string | A short description of the policy                                                                                |
| `description`   | string | A longer description of the policy                                                                               |
| `platform`      | array  | The platform describes the CSPs or other technology platform (e.g. Docker) that the rule checks for              |
| `remediation`   | object | [Remediation steps](#remediation) for the issue identified by the policy                                         |
| `references`    | object | Links to additional information about the issue identified by the policy                                         |
| `category`      | string | The category of the policy                                                                                       |
| `labels`        | array  | An array of labels (value-less tags) associated with this policy.                                                |
| `service_group` | string | The service group of the primary resource associated with this policy (e.g. "EBS", "EC2")                        |
| `controls`      | array  | An array of control IDs to map to a compliance control                                                           |
| `severity`      | string | The severity of the issue identified by this policy                                                              |
| `product`       | array  | An array of the products this policy supports                                                                    |
| `kind`          | string | The kind of results that the policy produces. Defaults to `vulnerability` if unset.                              |

Example with all fields populated:

```open-policy-agent
metadata := {
    "id": "COMPANY_0001",
    "kind": "vulnerability",
    "title": "S3 bucket name contains the word 'bucket'",
    "description": "It is unnecessary for resource names to contain their type.",
    "platform": ["AWS"],
    "remediation": {
      "console": "1. Go to the AWS console\n2. Navigate to the S3 service page\n3. ...",
      "cloudformation": "1. Find the corresponding AWS::S3::Bucket resource\n2. ...",
      "terraform": "1. Find the corresponding aws_s3_bucket resource\n2. ..."
    },
    "references": {
        "general": [
          {
            "title": "Some blog post",
            "url": "https://example.com/bucket-naming-conventions"
          }
        ],
        "terraform": [
          {
            "title": "Resource aws_s3_bucket",
            "url": "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket"
          }
        ]
    },
    "category": "Best Practices",
    "labels": [
        "Naming Conventions",
        "Pet Peeves"
    ],
    "service_group": "S3",
    "controls": {
        "CIS-AWS": {
          "v1.3.0": [
            "5.1",
            "5.2"
          ],
          "v1.4.0": [
            "6.7"
          ]
        }
    },
    "severity": "Critical"
}
```

#### Remediation

Policies can provide input-type specific remediation steps via the `remediation`
metadata field. If this field is set, the policy engine will, by default, pick a
remediation string from this field based on the current input type using the following
mapping:

| Input type   | Key in `remediation` object |
| :----------- | :-------------------------- |
| `tf_hcl`     | `terraform`                 |
| `tf_plan`    | `terraform`                 |
| `cfn`        | `cloudformation`            |
| `cloud_scan` | `console`                   |
| `k8s`        | `kubernetes`                       |
| `arm`        | `arm`                       |

Policies can also bypass this behavior by returning a `remediation` string in the
[info object returned by the `deny` judgement rule](#info-object-properties).

### `resources[info]`

The `resources` rule is used to define which resources which contributed to a result.
For the multi-resource and missing-resource policy archetypes, the policy engine uses
`resources` results to mark resources as passing. For this reason, resources should be
written to return results regardless of whether the policy as a whole would pass or fail 
a specific resource.

The `info` return value is set to an object that describes a single resource and
optionally:
* Its attributes that contributed to the policy result
* Its relation to the primary resource associated with the policy result
* User defined policy output (see [examples/12-context.rego](../examples/12-context.rego))
#### `info` object properties

| Field              |  Type  | Description                                                                                  |
| :----------------- | :----: | :------------------------------------------------------------------------------------------- |
| `resource`         | object | A [resource object](#resource-objects) to associate with a policy result                     |
| `primary_resource` | object | The primary [resource object](#resource-objects) associated with a policy result             |
| `attributes`       | array  | An array of [attribute paths](#attribute-paths) from the resource in the `resource` property |
| `correlation`      | string | A manually-specified [correlation ID](#correlation-ids)    
| `context`          | object | User defined policy output ([example](../examples/12-context.rego))  |

#### Correlation IDs

Internally, each `deny[info]` result has an identifier associated with it. That
identifier can be manually specified by setting the `correlation` property in the info
object. Otherwise, it's calculated from the resource's type, identifier, and namespace.


Similarly, `resources[info]` results have an associated identifier that can be set
manually via a `correlation` property. Otherwise it will be calculated from the resource
in the `primary_resource` attribute (if specified) or the `resource` attribute.

The policy engine will relate `resources` results with `deny` results that have the same
identifier.

#### Graph

The `graph` attribute is way for policies to output graph of resources that contributed
to a result. The graph is represented by a list of labeled edges that describe the
relationship between a `source` and a `target`. For example, a policy that tests whether
an application is connected to a load balancer could include this `graph` in its result
to describe which resources are involved in that connection and how they are related:

```open-policy-agent
{
  "graph": [
    {
      "source": load_balancer,
      "label": "exposes",
      "target": target_group,
    },
    {
      "source": target_group,
      "label": "exposes",
      "target": application,
    },
  ]
}
```

#### Examples

* [examples/05-advanced-primary-resource.rego](../examples/05-advanced-primary-resource.rego)
  demonstrates using the `primary_resource` attribute to specify that a
  `resources[info]` result is related to a specific deny result. Note that the deny
  result's correlation ID is calculated by default in this usage.
* [examples/06-advanced-correlation.rego](../examples/06-advanced-correlation.rego)
  demonstrates using a manually-specified correlation ID to relate a `resources[info]`
  result to a `deny[info]` result.
* [examples/04-advanced-resources.rego](../examples/04-advanced-resources.rego)
  demonstrates using the `resource` property on the info `object` when the `resources`
  rule is returning the primary resource. In this example, the `resources` rule only
  serves to enable the policy engine to identify passing resources.
## Policy archetypes

### Single-resource policy

Single-resource policies are distinguished by setting the
[`resource_type` rule](#resource_type) to a single resource type. The policy engine
evaluates single-resource policies by querying the `deny[info]` rule with the `input`
document set to a single [resource object](#resource-object)

By definition, single resource policies only interact with a single resource. Therefore,
the `vulnmap.resources()` function is not useable in single-resource policies.

#### Single-resource policy examples

* [examples/01-simple.rego](../examples/01-simple.rego)
* [examples/02-simple-attributes.rego](../examples/02-simple-attributes.rego)

### Multi-resource policy

Multi-resource policies are distinguished by setting the
[`resource_type` rule](#resource_type) to `"MULTIPLE"`. The policy engine evaluates
multi-resource policies by querying the `deny[info]` rule with the `input` document set
to the entire `State` object being evaluated. Although multi-resource policies can
access individual resources via the `input` document, they should use the
`vulnmap.resources()` function to retrieve resources from the input by resource type.

#### Multi-resource policy examples

* [examples/03-advanced.rego](../examples/03-advanced.rego)
* [examples/04-advanced-resources.rego](../examples/04-advanced-resources.rego)
* [examples/05-advanced-primary-resource.rego](../examples/05-advanced-primary-resource.rego)
* [examples/06-advanced-correlation.rego](../examples/06-advanced-correlation.rego)

### Missing-resource policy

Missing-resource policies are an extension of the Multi-resource policy archetype that
has at least one `deny[info]` rule that sets the `resource_type` field on the `info`
object instead of `resource`, e.g.:

```open-policy-agent
# We cannot pass a `resource` to the deny (since we don't have one!).  But we
# can specify a `resource_type` as metadata, to indicate what sort of resource
# was missing.
deny[info] {
	count(global_cloudtrails) == 0
	info := {
		"message": "At least one aws_cloudtrail must have include_global_service_events configured",
		"resource_type": "aws_cloudtrail",
	}
}
```

#### Missing-resource policy examples

* [examples/08-missing.rego](../examples/08-missing.rego)

## The `vulnmap` API

The policy engine provides a set of functions under the `vulnmap` namespace that can be
used by policies. To use them, policies should `import data.vulnmap`, like is shown in the
[multi-resource policy examples](#multi-resource-policy-examples).

### `vulnmap.resources(<resource type>)`

The `vulnmap.resources` function takes in a single resource type string and returns an
array of [resource objects](#resource-objects) of that type from the current `State`
being evaluated.
If no resources of that type are known an empty array is returned.

Internally, the policy engine tracks calls to `vulnmap.resources` (and
`vulnmap.query`) to produce the `resource_types` array in the results output. This
array may be used by downstream consumers to add context to policy results. For
example, a consumer may need to communicate that some policy results were
inconclusive if the resource types used by the policy were not surveyed. For
this reason, some policies should be written to call `vulnmap.resources` for a
particular type _only if_ that resource type exists in the input. See
[`vulnmap.input_resource_types`](#vulnmapinput_resource_types) below for an example of
this idiom.

`vulnmap.resources("some-type")` return equivalent results to (and is a special
case of) `vulnmap.query({"resource_type": "some-type", "scope": {}})`.

#### Example `vulnmap.resources` call and output

This example demonstrates the `vulnmap.resources` input and output in a REPL session:

```sh
$ ./policy-engine repl examples/main.tf
> import data.vulnmap
> vulnmap.resources("aws_cloudtrail")
[
  {
    "_filepath": "examples/main.tf",
    "_meta": {},
    "_namespace": "examples/main.tf",
    "_provider": "aws",
    "_tags": {},
    "_type": "aws_cloudtrail",
    "_id": "aws_cloudtrail.cloudtrail1",
    "id": "aws_cloudtrail.cloudtrail1",
    "include_global_service_events": true,
    "name": "cloudtrail1",
    "s3_bucket_name": "aws_s3_bucket.bucket1",
    "s3_key_prefix": "prefix"
  }
]
> 
```

### `vulnmap.query(<query>)`

Queries the input for resources.

The parameter is an object, with two permitted fields. The first is
"resource_type", which is expected to have a string value. The second, "scope"
is a set of key-value pairs where the values are strings. Under the default
engine configuration, this query scope is compared to the "input scope", which
is set at config load time. An IaC input might be expected to have "filename"
set, for example. The query scope acts as a filter. The empty object, `{}`, is
the most permissive query scope, so all resources in the input of the requested
type will be returned.

The library API provides a mechanism to influence the behavior of this builtin,
and to inject custom resource resolver logic. You can read more about how to add
custom resource resolvers
[here](library_usage.md#custom-resource-resolution).

A simple query:

```
vulnmap.query({
  "resource_type": "aws_cloudtrail",
  "scope": {},
})
```

Will return all aws_cloudtrail resources in the input, regardless of input scope
(i.e. what IaC file they came from, or for cloud resources, what account/region
metadata was added by the loader).

In an IaC context, this query:

```
vulnmap.query({
  "resource_type": "aws_cloudtrail",
  "scope": {
    "filename": "main.tf",
  },
})
```

Will return all aws_cloudtrail resources found in main.tf. In a cloud context,
in which the loaders are presumably setting input scope to various cloud
attributes such as region/account, instead of IaC file names, this query will
return nothing.

When a query returns nothing due to a scope mismatch, the chain of custom
resource resolvers will be invoked. Optionally, the library client's custom
resolvers might fetch such resources from a place other than the input.

This query:

```
vulnmap.query({
  "resource_type": "aws_cloudtrail",
  "scope": {
    "foo": "bar",
  },
})
```

Will return nothing, unless a UPE config loader happens to set the "foo" input
scope field, which doesn't seem likely! The exact input scope fields set by
loaders are specific to the environment of that loader (e.g. cloud
region/account, or IaC filename, module name).

UPE policies that make queries with specific scope will likely be rarer than
ones that do not, because they implicitly rely on the behavior of loaders and/or
custom resolvers. Queries that do not make use of specific scope, only
requesting resources by type, can use `vulnmap.resources()` instead if the author
wishes, which is backed by the same implemenation as `vulnmap.query()`, but should
never trigger the custom resolver chain, since the most permissive scope is
always used.

### `vulnmap.relates(<resource>, <relation name>)`

`vulnmap.relates` returns a list of right resources that match the given left
resource and relationship name.

For more info, see:

 -  [This example](../examples/05-advanced-resource-relations.rego)
 -  [The resource relations design](design/resource-relations.md)
 -  [Resource relations specification](#resource-relations-specification)

#### `vulnmap.back_relates(<relation name>, <resource>)`

`vulnmap.back_relates` is the inverse of `vulnmap.relates`, and returns a list of left
resources that match the given right resource and relationship name.

#### `vulnmap.relates_with(<resource>, <relation name>)`

`vulnmap.relates_with` is a version of `vulnmap.relates` that returns a list of
pairs of `[resource, annotation]` rather than just a list of resources.

#### `vulnmap.back_relates_with(<relation name>, <resource>)`

`vulnmap.back_relates_with` is a version of `vulnmap.back_relates` that returns a list
of pairs of `[resource, annotation]` rather than just a list of resources.

### `vulnmap.input_resource_types`

`vulnmap.input_resource_types` is a `set` of all resource types in the input. This can be
useful in policies that _can_ check multiple resource types, but don't _require_ them to
produce conclusive results. A common example of this type of policy is one that enforces
specific tags across many different resource types. Another common example are policies
that are written to work with multiple [input types](#input_type), like policies with
the `tf` input type.

#### Example vulnmap.input_resource_types usage

This example is from a policy that's written for the `tf` input type. `tf` is an
aggregate input type that includes some IaC inputs as well as the `cloud_scan` input
type. This means that it will be used to evaluate both IaC and live, running
infrastructure.

```open-policy-agent
# Here we're producing an object of data.aws_iam_policy_document resources. This
# resource type is an abstraction provided by Terraform and doesn't map to any "real"
# deployed resource type. So, we only want to enumerate these resources when they exist
# in the input to avoid reporting this resource type for cloud_scan inputs.
# 
# The result is that when no data.aws_iam_policy_document resources exist in the input,
# this object will be empty.
policy_documents := {id: doc |
	vulnmap.input_resource_types["data.aws_iam_policy_document"]
	doc := vulnmap.resources("data.aws_iam_policy_document")[_]
}
```

### `vulnmap.input_type`

`vulnmap.input_type` gets set to the [input type](#input_type) of the current input being
evaluated. This can be useful in policies that are written for multiple but only need to
enforce a particular condition in one of those input types.

#### Example `vulnmap.input_type` usage

This is example is taken from a policy that enforces some configuration on
`aws_iam_account_password_policy` resources. For `cloud_scan` inputs, we also want to
enforce that this resource exists (as in the
[Missing Resource policy archetype](#missing-resource-policy)).

```open-policy-agent
password_policy_type := "aws_iam_account_password_policy"

password_policies := vulnmap.resources(password_policy_type)
password_policy_exists {
  _ = password_policies[_]
}

deny[info] {
  pol := password_policies[_]
  pol.minimum_password_length < 14
  info := {
    "resource": pol
    "attributes" [["minimum_password_length"]]
  }
}

deny[info] {
  # We only want this condition to apply to cloud_scan inputs
  vulnmap.input_type == "cloud_scan"
  info := {
    "resource_type": password_policy_type,
    "message": "No IAM password policy was found."
  }
}
```

### `vulnmap.terraform.resource_provider_version_constraint(<resource>, <constraint>)`

This function takes a resource and a version constraint for the terraform
provider, for example `">= 4"` or `"~>3, != 3.0.1"`.  You can see the full
syntax for the version constraints here:
<https://www.terraform.io/language/expressions/version-constraints>.

Keep in mind that in many cases, we don't know the exact provider version that
is being used.  We can only deduce constraints from `required_providers` blocks:

```hcl
terraform {
  required_providers {
    aws = {
      version = "~> 4.0.0"
    }
  }
}
```

So this function checks if the version constraint specified in the argument
is _compatible_ with all the requirements.  This means that if there are
no requirements, this function will always return `true`.

## Resource relations specification

This is only a brief specification, to better understand this, see:

 -  [This example](../examples/relations.rego)
 -  [The resource relations design](design/resource-relations.md)

Relationships are defined in separate files and must extend the
`data.relations.relations` set:

```rego
package relations

import data.vulnmap

relations[info] {
	info := {
		...
	}
}
```

`info` has the following properties:

| Field      |  Type  | Description                                                                                                  |
| :--------- | :----: | :----------------------------------------------------------------------------------------------------------- |
| `name`     | string | Name for the relationship                                                                                    |
| `keys`     | object | An object with `left` and `right` arrays containing `[resource, key]` or `[resource, key, annotation]` items |
| `explicit` | array  | An explicit of list of `[left, right]` or `[left_resource, right_resource, annotation]` items                |

`name` is required, and one of `keys` and `explicit` must be specified.

## Types reference

This section describes some of the types referred to in the other sections of this
document.

### State object

"State object" refers to the input to the policy engine's policy evaluation. The state
object is defined in the [`swagger.yaml` file](../swagger.yaml), which is then used to
generate [a model struct](../pkg/models/model_state.go).

In general, policies should not interact with the state object directly and should
instead use [the `vulnmap` API](#the-vulnmap-api).

### Resource objects

Resource objects are a map of resource property name to property value. Policy authors
can expect that resource objects are close or identical to how the resources are defined
in IaC code with some additional properties added by the policy engine.

For example, the following Terraform resource:

```hcl
resource "aws_cloudtrail" "cloudtrail1" {
  name                          = "cloudtrail1"
  s3_bucket_name                = aws_s3_bucket.bucket1.id
  s3_key_prefix                 = "prefix"
  include_global_service_events = true
}
```

would become the following resource object:

```json
{
  "_filepath": "examples/main.tf",
  "_meta": {},
  "_namespace": "examples/main.tf",
  "_provider": "aws",
  "_tags": {},
  "_type": "aws_cloudtrail",
  "_id": "aws_cloudtrail.cloudtrail1",
  "id": "aws_cloudtrail.cloudtrail1",
  "include_global_service_events": true,
  "name": "cloudtrail1",
  "s3_bucket_name": "aws_s3_bucket.bucket1",
  "s3_key_prefix": "prefix"
}
```

Policy Engine adds two ID fields to the resource object that policies can use in
their assertions:

* `_id`: this will always contain the "logical ID" of the resource
  * In IaC, logical IDs are typically how resources are referenced in the source
    code.
  * The example above demonstrates a logical ID from Terraform
* `id`: this will contain the resource's `id` attribute if: it exists, it is
  non-null, and it is non-blank. Otherwise, it will contain the logical ID.
  * This flexibility can be helpful for writing assertions that work with both
    IaC and deployed resources.

#### Obtaining resource objects

In [single-resource policies](#single-resource-policy), the `input` document will be
set to a single resource object of the type specified in the
[`resource_type` rule](#resource_type).

In [multi-resource policies](#multi-resource-policy) and
[missing-resource policies](#missing-resource-policy), resource objects should be
obtained via the [`vulnmap.resources`](#vulnmapresourcesresource-type) function.

### Attribute paths

Attribute paths are arrays of strings and integers that describe the location of a
particular attribute within a resource. For example, given the following JSON
attributes:

```json
{
  "ingress": [
    {
      "from_port": 22,
      "to_port": 22
    }
  ]
}
```

The path to `from_port` would be `["ingress", 0, "from_port"]`.


The `attributes` properties that you see in the [`deny`](#denyinfo) and
[`resources`](#resourcesinfo) definitions are arrays of attribute paths, e.g:

```open-policy-agent
[
    [
        "spec",
        0,
        "container",
        1,
        "security_context",
        0,
        "privileged"
    ],
    [
        "spec",
        0,
        "container",
        3,
        "security_context",
        0,
        "privileged"
    ]
]
```

The following examples demonstrate how `attributes` can be used in practice:

* [`examples/02-simple-attributes.rego`](../examples/02-simple-attributes.rego)
* [`examples/07-advanced-attributes.rego`](../examples/07-advanced-attributes.rego)
