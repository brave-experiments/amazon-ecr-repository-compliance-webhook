/*
  Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
  Licensed under the Apache License, Version 2.0 (the "License").
  You may not use this file except in compliance with the License.
  A copy of the License is located at
      http://www.apache.org/licenses/LICENSE-2.0
  or in the "license" file accompanying this file. This file is distributed
  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
  express or implied. See the License for the specific language governing
  permissions and limitations under the License.
*/

package main

import (
	"context"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/brave-intl/amazon-ecr-repository-compliance-webhook/pkg/function"
)

var (
	cfg, err  = config.LoadDefaultConfig(context.TODO())
	ecrClient = ecr.NewFromConfig(cfg)

	// Handler is the handler for the validating webhook.
	Handler = function.NewContainer(*ecrClient).Handler().WithLogging().WithProxiedResponse()

	// Version is the shortened git hash of the binary's source code.
	// It is injected using the -X linker flag when running `make`
	Version string
)

func main() {
	lambda.Start(Handler)
}
