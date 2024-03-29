+++
title = "pam resource"
draft = false
gh_repo = "inspec"
platform = "unix, linux"

[menu]
  [menu.inspec]
    title = "pam"
    identifier = "inspec/resources/os/pam.md pam resource"
    parent = "inspec/resources/os"
+++

Use the `pam` Chef InSpec audit resource to test the ...


## Availability

### Installation

This resource is distributed along with Chef InSpec itself. You can use it automatically.

## Syntax

A `pam` Chef InSpec audit resource ...

    describe pam do
      its('shoe_size') { should cmp 42 }
      it { should be_purple }
      it { should have_bells }
    end
where

- `'shoe_size'` is some property of this resource
- `42` is the value to test for shoe size
- `be_purple` is a matcher of this resource
- `have_bells` is a matcher of this resource

## Properties

- Properties of the resources: `shoe_size`

### shoe_size

The shoe_size property tests ....

## Matchers

For a full list of available matchers, please visit our [matchers page](https://docs.chef.io/inspec/matchers/).

The specific matchers of this resource are: `be_purple`, `have_bells`

### be_purple

The `be_purple` matcher tests the ...:

    it { should be_purple }

## Examples
The following examples show how to use this Chef InSpec audit resource.

### Example 1

`shoe_size` returns ...

    describe pam do
      its("shoe_size") { should eq 42 }
    end

### Example 2

`be_purple` checks for ...

    describe pam do
      it { should be_purple }
    end

