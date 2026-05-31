# AKS GitOps Sample App

This repository contains a small Kubernetes sample application for GitOps practice on AKS.

It is designed to be used by labs that demonstrate:

- Argo CD
- Flux
- Environment promotion
- Blue/green deployment
- Canary deployment
- Incident troubleshooting

## Structure

    k8s/base
      Shared Kubernetes manifests

    k8s/overlays/dev
      Dev environment overlay

    k8s/overlays/qa
      QA environment overlay

    k8s/overlays/prod
      Production environment overlay

## Default app

The sample app uses the public NGINX image and a ConfigMap-backed custom index page.

No private registry is required.
