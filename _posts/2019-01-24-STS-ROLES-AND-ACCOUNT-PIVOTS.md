---
layout: post
title:  "STS Roles and Multi-Account Pivoting"
date:   2019-01-24 23:46:50 -0500
categories: aws sts roles
---

# STS ROLES and MULTI-ACCOUNT PIVOTING

## Overview

During a recent audit of AWS accounts I noticed the lack of a solid way to review the relationship of STS roles between accounts. The problem is, you can easily see what accounts you're granting access to, but going the other direction is an exercise in patience. I wanted to know, *given a number of AWS credentials, how specific accounts were related to one another*. If I could obtain that information, I would be well on my way to discovering pivot points between AWS accounts.

## Multi-Account Deployments

In AWS, the concept of multi-account deployments isn't new. It's a fantastic way to achieve data and operational isolation. It allows you to grant specific access to components of your own account and easily separate environments like Staging and Production. From a user management perspective, it also allows for an interesting method of control using role assumption

## Enabling a Role

AWS allows for the creation of a role, which is then assumable by an external account. This is an interesting concept overall because the default implementation implicitly trusts the entire external account. 

![EC2 Role](/assets/images/ec2forderekfrombob.png)

This leaves the user management and ability to assume roles up to the entity being granted access, and the permissions that are obtained as a result of that assumption to the entity granting the access. 

Again by default, this is to the entire accounted being granted the access

As an example, if I am Bob's Honey Bees account and I want to allow my distributor to access my EC2 instances. I can create a role granting read access to EC2, and provide that access to Derek's Distribution.

Now Derek, being a pretty big deal, grants assume role capabilities to only his most trusted employees to take over this EC2 role in Bob's account. Bob has no idea who has access to assume a role and Derek's employees don't have any idea what roles they CAN assume, unless they are provided with the account number or guidance by Derek. Now, Bob COULD discuss terms of this role relationship with Derek and restrict access to a specific user in the Derek's Distribution account, but that's not the default.

So in this limited sense, anyone with the assumerole capability in Derek's Distribution has full access to the role provided by Bob's Honey Bees.

If any of the privileged accounts in Derek's distribution are compromised, they theoretically have access to Bob's Bees via this EC2 role, but an attacker wouldn't necessarily be aware that they have access thorugh this compromised account.

## Complicated

The complication starts when multiple accounts are compromised. Enter Bob's IAM administrator. This guy, let's call him James, only has read access to IAM in Bob's Honey Bee's. This is really great because Bob doesn't know anything about IAM and needs James to review policies and permissions. James is pretty careless with his AWS creds, but Bob's not too worried about them being on pastebin, because honestly he's only got access to this small slice of his AWS console world.

If an attacker is able to obtain aws credentials in the wild, there is a rare occasion that two accounts might be connected to create an interesting pivot point. In this case any compromised account on Derek's Distribution with assume role capabilities and an account with read access to IAM on Bob's Honey Bees, like James.

So now, I have James' (from Bob's) credentials, and I've got Johnny's credentials. Johnny is a new guy over at Derek's with the assume role capability. He's also a pastebin afficionado.

How would I ever know that these accounts are even remotely connected?

## Quick Recap

Either as an auditor or a lucky researcher I've got two users from separate accounts with list roles permissions, and ONE of these users has the ability to assume a role in another account

![Roles and Accounts](/assets/images/Roles.png)

## Enter an enumeration script:

This script will run through all credentials in the profiles you specify based on your boto3 credentials file and show you any links that will provide you with some potential pivoting.

```
import boto3

# Use profiles that exist in your ~/.aws/credentials file
# Add to the array with any additional profiles for this to work i.e. ["default","profile0","profile1"] etc.
profiles = ["default"] 

assumable_accounts = {}
assuming_accounts = []

# Iterate over Profiles
for profile in profiles:
	dev = boto3.session.Session(profile_name=profile)
	print "*******************"
	print "ENUMERATING Profile"
	print "*******************"

	# Set the profile
	current_account = dev.client('sts').get_caller_identity().get('Account')
	
	print(profile + ":" + current_account)
	
	client = dev.client('iam', region_name="us-east-1")
	response = client.list_roles()
	
	# Get Roles that are Assumable by other AWS Accounts (Currently doesn't include those managed by SCP)
	roles = response.get("Roles")
	assumable_accounts[current_account] = []
	print "___________________________________________________________________"
	print "Roles that can be Assumed by Other AWS Accounts:"
	print "___________________________________________________________________"
	for role in roles:
		if "AWS" in role["AssumeRolePolicyDocument"]["Statement"][0]["Principal"]:
			print(role["RoleId"] + "/" + role["RoleName"])
			assumable_role = role["AssumeRolePolicyDocument"]["Statement"][0]["Principal"]["AWS"]+ "/" + role["RoleName"]
			assumable_accounts[current_account].append(assumable_role)

print "**************************************************************"
print "*Iteration on what can be assumed with the provided Profiles:*"
print "**************************************************************"

# Find out if your profiles can talk to each other and through what roles
for account in assumable_accounts:
	print "___________________________________________________________________"
	print "ACCOUNT: " + account + " contains the following assumable accounts:"
	print "___________________________________________________________________"

	for role in assumable_accounts[account]:
		for search_account in assumable_accounts:
			if search_account in role:
				print "You have access to the " + search_account + " account which can be used to assume -> " + role
			
```

And Kazaam!

![Script Output](/assets/images/scriptoutput.png)

We can see that my compromise of James allows me to see that Johnny can assume the EC2 Read role, and that there is an additional assumable administrative role. This allows me to connect some dots and gain some additional information on the second account. There is also the potential that additional account roles are shared to external accounts and sometimes this is an administrative role. 

![Switch Roles](/assets/images/switching-roles.png)

![Logged In](/assets/images/logged-in-as-new-role.png)

For Public AWS credential collectors, this is useful - especially where support organizations are provided assumable roles to many clients.

I hope this short post is helpful or in the very least interesting, and if you want to give the script a go for yourself, check out my gist.

https://gist.github.com/relotnek/d9fc32be9ae5658426c64e7951b30c28

-Ken
