// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package function

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/ecr/types"
	"github.com/aws/aws-sdk-go/aws"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
)

const digestID = "@"

var registryId = os.Getenv("REGISTRY_ID")

// From repository:tag to repository, tag
// Or repository@sha256:digest to repository, @sha256:digest
func parts(image string) (repo, tagOrDigest string) {
	if strings.Contains(image, digestID) {
		segments := strings.Split(image, digestID)
		repo, tagOrDigest = segments[0], digestID+segments[1] // append ampersand for later
		log.Tracef("parts: repo [%s], tagOrHash [%s]", repo, tagOrDigest)
		return
	}
	segments := strings.Split(image, ":")
	repo, tagOrDigest = segments[0], segments[1]
	log.Tracef("parts: repo [%s], tagOrHash [%s]", repo, tagOrDigest)
	return
}

// CheckRepositoryCompliance checks if the container image that was sent to the webhook:
// 1. Comes from an ECR repository
// 2. Has image tag immutability enabled
// 3. Has image scan on push enabled
// 4. Does not contain any critical vulnerabilities
func (c *Container) CheckRepositoryCompliance(ctx context.Context, image string) (bool, error) {
	repo, _ := parts(image)
	input := &ecr.DescribeRepositoriesInput{
		RepositoryNames: []string{repo},
		RegistryId:      &registryId,
	}

	output, err := c.ECR.DescribeRepositories(ctx, input)
	if err != nil {
		return false, err
	}

	if len(output.Repositories) == 0 {
		return false, fmt.Errorf("no repositories named '%s' found", repo)
	}
	r := output.Repositories[0]
	if r.ImageTagMutability == types.ImageTagMutabilityMutable {
		return false, fmt.Errorf("repository '%s' does not have image tag immutability enabled", repo)
	}
	if !r.ImageScanningConfiguration.ScanOnPush {
		return false, fmt.Errorf("repository '%s' does not have image scan on push enabled", repo)
	}
	critical, err := c.HasCriticalVulnerabilities(ctx, image)
	if err != nil {
		return false, err
	}
	if critical {
		return false, fmt.Errorf("image '%s' contains %s vulnerabilities", image, types.FindingSeverityCritical)
	}
	return true, nil
}

// BatchCheckRepositoryCompliance checks the compliance of a given set of ECR images.
// False is returned if a single repository is not compliant.
func (c *Container) BatchCheckRepositoryCompliance(ctx context.Context, images []string) (bool, error) {
	g, ctx := errgroup.WithContext(ctx)
	compliances := make([]bool, len(images))

	for i, image := range images {
		i, image := i, image // shadow
		g.Go(func() error {
			compliant, err := c.CheckRepositoryCompliance(ctx, image)
			compliances[i] = compliant
			return err
		})
	}
	if err := g.Wait(); err != nil {
		return false, err
	}

	for _, complaint := range compliances {
		if !complaint {
			return false, nil
		}
	}
	return true, nil
}

// HasCriticalVulnerabilities checks if a container image contains 'CRITICAL' vulnerabilities.
func (c *Container) HasCriticalVulnerabilities(ctx context.Context, image string) (bool, error) {
	var (
		repo, tagOrDigest = parts(image)
		found             = false
	)
	input := &ecr.DescribeImageScanFindingsInput{
		ImageId:        &types.ImageIdentifier{},
		RepositoryName: aws.String(repo),
		RegistryId:     &registryId,
	}

	switch strings.Contains(tagOrDigest, digestID) {
	case true:
		input.ImageId.ImageDigest = aws.String(tagOrDigest[1:]) // omit ampersand
	default:
		input.ImageId.ImageTag = aws.String(tagOrDigest)
	}

	output, err := c.ECR.DescribeImageScanFindings(ctx, input)
	if err != nil {
		return false, err
	}

	for _, finding := range output.ImageScanFindings.Findings {
		if finding.Severity == types.FindingSeverityCritical {
			found = true
			return found, nil
		}
	}

	return found, nil
}
