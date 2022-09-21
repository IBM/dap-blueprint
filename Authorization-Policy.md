# Authorization Policy

DAP Blueprint implements transaction authorization rules for Bitcoin transactions defined at [a document](https://github.com/swisschain/Rule-Engine-Docs).

## Approval Rules

The policy service invokes a `validate` method with a `psbt`, an array of pre-hash values and the user id. The `psbt` stands for *Partially Signed Bitcoin Transaction*, defined in [BIP-174](https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki) and [BIP-370](https://github.com/bitcoin/bips/blob/master/bip-0370.mediawiki). It is a raw Bitcoin transaction before signed. A pre-hash value is to be signed by the signing service.

First, the validate method validates each pre-hash value by recomputing it from the `psbt`. The policy service rejects the transaction if at least one of the pre-hash values doesn't match with the recomputed value. 

<!-- Second, the method checks if [the transaction amount doesn't exceed an absolute limit](https://github.com/swisschain/Rule-Engine-Docs/blob/master/Technical%20requirement%20for%20POC/1.%20Description%20of%20the%20use%20case%20and%20requirements.md#4--it-is-forbidden-to-transfer-large-amounts-for-a-single-transaction-using-btc-and-eth) (e.g. 40 BTC). The amount is the summation of the amount of all outputs in the `psbt` except for the output to one or more `change` addresses. This rule approves the transaction if the amount isn't more than the limit. -->

Second, the method checks if [the transaction amount doesn't exceed an automatic approval limit](https://github.com/swisschain/Rule-Engine-Docs/blob/master/Technical%20requirement%20for%20POC/1.%20Description%20of%20the%20use%20case%20and%20requirements.md#1--the-transaction-with-btc-and-eth-and-not-a-small-amount-should-be-approved-by-2-employees-of-the-customer-support-department-or-jon-from-the-finance-control-department) (e.g. 1 BTC). When the amount is more than the limit, the policy service sends an email to officers of the customer support department and one officer of the finance department for approvals. Each officer of the customer support department can vote with one weight, while the officer of the finance department can vote with two weights. The policy service needs to get two votes (weights) to approve. The amount is computed in the same way as the previous rule. This rule approves the transaction if the amount isn't more than the limit or if it collects enough votes from the officers. 

Third, the method checks if [the daily total amount from the same user doesn't exceed a daily limit](https://github.com/swisschain/Rule-Engine-Docs/blob/master/Technical%20requirement%20for%20POC/1.%20Description%20of%20the%20use%20case%20and%20requirements.md#2--with-an-abnormally-large-volume-of-transfers-during-the-day-transactions-should-be-approved-by-someone-from-the-finance-control-department) (e.g. 10 BTC). When the daily total is more than the limit, the policy service sends an email to all officers of the finance department (including the head of the department). The policy service needs to get one vote to approve. The daily total is the summation of the amount of al outputs initialed by the same user specified by the `user id`, excluding amounts to a `change` address. This rule approves the transaction if the daily total isn't more than the limit or if it collects enough votes from the officers.

The policy service remembers the transaction amount for all approved transactions for one day to compute the daily total amount. The policy service looks up all approved transactions for a given user within 24 hours, and checks if each transaction actually happened by querying it against the public Bitcoin blockchain.

The policy service approves the transaction if all rules approve it, or rejects the transaction if any of the rules reject it.

Here is a pseudo code to describe the approval rules. The `validate` method is called when the policy service retrieves a transaction queue.

```
func validate(psbt, prehash[], userid) {
    // First, check each pre-hash value.
    for each index in prehash[] {
        h = compute_prehash(psbt, index)
        if h != prehash[index] {
            reject_transaction(psbt)
            return
        }
    }
    total_amount = 0
    for each output in psbt {
        if output_address(output) is not dervied from the sender's seed {
            total_amount = total_amount + output_amount(output)
        }
    }
    pending = False
    // Second, send an approval request if the amount exceeds an automatic approval limit ("rule2").
    if total_amount > automatic_approval_limit {
        store_pending_transaction(psbt, userid, "rule2", approvers_rule3[])
        send_email_to_approvers(psbt, "rule2", approvers_rule3[])
        pending = True
    }
    daily_total_amount = total_amount
    for each transaction within the last 24 hours {
        if transaction.userid == userid and found_in_public_blockchain(transaction) {
            daily_total_amount = daily_total_amount + transaction.total_amount
        }
    }
    // Third, send an approval request if the amount exceeds an automatic approval daily limit ("rule3").
    if daily_total_amount > automatic_approval_daily_limit {
        store_pending_transaction(psbt, userid, "rule3", approvers_rule3[])
        send_email_to_approvers(psbt, "rule3", approvers_rule3[])
        pending = True
    }
    if pending == False {
        approve_transaction(psbt)
    }
}
```

The `on_approver_response` method is called when the policy service receives a response from an approver.

```
func on_approver_response(psbt, ruleid, approval, approverid) {
    tx_record = retreive_pending_transaction(psbt)
    if approverid not in tx_record.rules[ruleid].approvers {
        retrun "error: not in the approver list"
    }
    if tx_record.rules[ruleid].approval[approverid] is not None {
        return "error: already voted"
    }
    tx_record.rules[ruleid].approval[approverid] = approval
    if approval == True {
        tx_record.rules[ruleid].num_approvals = tx_record.rules[ruleid].num_approvals + 1
    } else {
        tx_record.rules[ruleid].num_rejects = tx_record.rules[ruleid].num_rejects + 1
    }
    if tx_record.rules[ruleid].num_rejects > (rules[ruleid].num_approvers - rules[ruleid].quorum_size) {
        reject_transaction(pbst)
    }
    not_yet_approved = False
    for each ruleid in rules {
        if tx_record.rules[ruleid].num_approvals < rules[ruleid].quorum_size {
            not_yet_approved = True
        }
    }
    if not_yet_approved == False {
        approve_transaction(pbst)
    }
}
```

## Red Hat Process Automation Manager for Approvers

DAP Blueprint uses Red Hat Process Automation Manager (RHPAM) to define rules. Actually, the rules mentioned above are defined by using a GUI tool of RHPAM. Therefore, once an officer receives an email notification, he/she can approve or reject a transaction on a GUI tool on RHPAM (RHPAM).

An approver can get a list of approval requests being assigned to him/her from a RHPAM server. Each request has the following information.
 - Process Instance ID in RHPAM
 - User ID initiating this transaction
 - Amount to be sent
 - Total amount to be sent within 24 hours
 - `psbt`

## REST API for Approvers

When an approver wants to know the details of a transaction in an approval request, he/she can query the details to an approval server by calling REST APIs with a process instance ID. For example he/sh can retrieve the details of the `pbst` in a json format, which include the outputs and inputs of the transaction. An approver can also get a list of transactions within the specified hours from the same user to examine the history of transactions. REST APIs for approvers can be found [here](https://ibm.github.io/dap-blueprint).

