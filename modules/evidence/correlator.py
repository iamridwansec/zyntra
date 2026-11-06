def correlate_observations(observations):
    """
    Correlate JavaScript endpoint and potential-secret observations
    that originate from the same JavaScript file.
    """
    javascript_files = {}

    for index, observation in enumerate(observations):
        if observation.category not in ("js_endpoint", "potential_secret"):
            continue

        javascript_url = observation.data.get("javascript_url")

        if not javascript_url:
            continue

        javascript_files.setdefault(javascript_url, {
            "endpoints": [],
            "potential_secrets": []
        })

        if observation.category == "js_endpoint":
            javascript_files[javascript_url]["endpoints"].append(index)
        else:
            javascript_files[javascript_url]["potential_secrets"].append(index)

    correlations = []

    for javascript_url, evidence in javascript_files.items():
        if not evidence["endpoints"] or not evidence["potential_secrets"]:
            continue

        correlations.append({
            "correlation_type": "javascript_endpoint_with_potential_secret",
            "confidence": "contextual",
            "javascript_url": javascript_url,
            "endpoint_count": len(evidence["endpoints"]),
            "potential_secret_count": len(evidence["potential_secrets"]),
            "related_observations": (
                evidence["endpoints"] + evidence["potential_secrets"]
            )
        })

    return correlations
