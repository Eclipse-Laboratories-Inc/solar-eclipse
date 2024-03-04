#!/bin/bash

# BRANCH="-${GITHUB_HEAD_REF}:$AAA"
# TOBRANCH="${{ env.ENV }}"
# IMAGE_TAG="${TOBRANCH}-${COMMIT_HASH}"
# VERGEN_SHA_EXTERN="${IMAGE_TAG}"

# GITHUB_HEAD_REF: The head ref or source branch of the pull request in a workflow run
# GITHUB_REF_NAME: The short ref name of the branch or tag that triggered the workflow run
BRANCH_NAME="${GITHUB_HEAD_REF:-$GITHUB_REF_NAME}"
COMMIT_SHA="${GITHUB_SHA:0:7}"
IMAGE_TAG="${BRANCH_NAME}-${COMMIT_SHA}"
REGION=$(curl http://169.254.169.254/latest/dynamic/instance-identity/document | grep region | awk -F\" '{print $4}')

env | sort
echo "BRANCH_NAME: ${BRANCH_NAME}"
echo "COMMIT_SHA: ${COMMIT_SHA}"
echo "IMAGE_TAG: ${IMAGE_TAG}"
echo "REGION: ${REGION}"
echo "ECR: ${ECR}"

aws ecr get-login-password --region "${REGION}" | docker login --username AWS --password-stdin "${ECR}"
