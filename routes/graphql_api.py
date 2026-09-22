from ariadne import graphql_sync
from flask import Blueprint, jsonify, request
from flask_login import current_user, login_required

from graphql_api.schema import schema

graphql_bp = Blueprint("graphql_api", __name__, url_prefix="/graphql")


@graphql_bp.route("", methods=["GET"])
@login_required
def graphql_info():
    # No interactive explorer here: Ariadne's built-in GraphiQL/Playground
    # pages load their JS from a CDN, which this app's strict
    # `Content-Security-Policy: default-src 'self'` blocks. POST a
    # standard { "query": "..." } body to this same URL instead.
    return jsonify({
        "message": "GraphQL API. POST a JSON body with a 'query' field to this endpoint.",
        "queries": ["scanStatus(scanId: Int!)", "liveCharts", "recentFindings(limit: Int)"],
    })


@graphql_bp.route("", methods=["POST"])
@login_required
def graphql_endpoint():
    data = request.get_json(silent=True) or {}
    success, result = graphql_sync(
        schema,
        data,
        context_value={"user": current_user},
        debug=False,
    )
    status = 200 if success else 400
    return jsonify(result), status
