import datetime
import os

import jwt
import requests

import pymongo
from flask import Flask, abort, request
from flask_restplus import Api, Resource, fields

app = Flask(__name__)
api = Api(app)
CUBS_DB = pymongo.MongoClient(os.getenv("MONGO_URI")).cubs

api.config["JWT_SECRET"] = os.getenv("JWT_SECRET")
api.config["JWT_ALGO"] = os.getenv("JWT_ALGO")
api.config["ALLOWED_EMAILS"] = os.getenv("ALLOWED_EMAILS").split(":")
api.config["GOOGLE_OAUTH_URI"] = os.getenv("GOOGLE_OAUTH_URI")
api.config["GOOGLE_CLIENT_ID"] = os.getenv("GOOGLE_CLIENT_ID")


login_fields = api.model(
    "Login", {"token": fields.String(required=True, description="Google OAuth2 token")}
)

boomerang_subtask_fields = api.model(
    "BoomerangSubTask",
    {
        "topic": fields.String(required=True, description="Subtask's topic"),
        "task": fields.String(required=True, description="Description of the subtask"),
        "completed": fields.Datetime(required=False, description="Date of completon"),
    },
)

boomerang_task_fields = api.model(
    "BoomerangTask",
    {
        "name": fields.String(required=True, description="Name of the task"),
        "requiredSubtasks": fields.Int(
            required=False,
            description="Required number of sub tasks, if omitted then default is all",
        ),
        "subTasks": fields.List(
            boomerang_subtask_fields,
            required=True,
            description="Sub tasks to complete the boomerang task",
        ),
        "completed": fields.Date(required=False),
    },
)

badge_section_fields = api.model(
    "BadgeSection",
    {
        "name": fields.String(require=True),
        "requiredTasks": fields.Integer(required=True),
        "tasks": fields.List(
            {
                "description": fields.String(required=True),
                "completed": fields.Date(required=False),
            },
            required=True,
        ),
        "completed": fields.Date(required=False),
    },
)

achievement_badge_fields = api.model(
    "AchievementBadge",
    {
        "name": fields.String(required=True),
        "level": fields.Integer(required=True),
        "requiredSections": field.Integer(requied=True),
        "sections": fields.List(field.Nested(badge_section_fields), required=True),
        "completed": fields.Date(required=False)
    },
)

special_interest_badge_fields = api.model(
    "SpecialInterestBadge",
    {
        "name": fields.String(required=True),
        "activities": fields.List(
            {
                "description": fields.String(required=True),
                "completed": fields.Date(required=True),
            }
        ),
        "completed": fields.Date(required=False),
    },
)

new_cub_fields = api.model(
    "NewCub",
    {
        "name": fields.String(description="Cub's name", required=True),
        "DOB": fields.DateTime(required=True),
        "greyWolf": fields.Nested(
            grey_wolf_fields, attribute="grey_wolf", required=True
        ),
        "goldBoomerang": fields.List(
            fields.Nested(boomerang_task_fields),
            attribute="gold_boomerang",
            required=True,
        ),
        "silverBoomerang": fields.List(
            fields.Nested(boomerang_task_fields),
            attribute="silver_boomerang",
            required=True,
        ),
        "bronzeBoomerang": fields.List(
            fields.Nested(boomerang_task_fields),
            attribute="bronze_boomerang",
            required=True,
        ),
        "achievementBadges": fields.List(
            fields.Nested(achievement_badge_fields),
            attribute="achievement_badges",
            required=True,
        ),
        "specialInterestBadges": fields.List(
            fields.Nested(special_interest_bage_fields),
            attribute="special_interest_badges",
            required=True,
        ),
    },
)

update_cub_fields = api.model("UpdateCub", new_cub_fields)
for field in update_cub_fields.keys():
    update_cub_fields[field].required = False

def validate_google_token(token):
    """Validate that TOKEN is a valid token from Google OAuth2."""
    if not token:
        api.logger.info("Empty token, denying access")
        return False

    resp = requests.get(api.config["GOOGLE_OAUTH_URI"], params={"id_token": token})

    if not resp.ok:
        api.logger.info("Request to %s failed: %s", resp.url, resp.status_code)
        return False

    if resp.status_code != 200:
        api.logger.info("Unexpected status code: %s", resp.status_code)
        return False

    resp = resp.json()

    # Make sure the ISS claim is as expected
    if resp.get("iss") not in ["accounts.google.com", "https://accounts.google.com"]:
        api.logger.info("Unexpected value in iss field: %s", resp.get("iss"))
        return False

    # Make sure the token is not expired
    exp = resp.get("exp")
    if not exp:
        api.logger.info("Expected exp field but it does not exist in %s", str(resp))
        return False

    if datetime.fromtimestamp(exp) >= datetime.timestamp():
        api.logger.info("Token has expired (exp %s)", exp)
        return False

    # Make sure the aud claim is as expected
    if resp.get("aud") != api.config["GOOGLE_CLIENT_ID"]:
        api.logger.info(
            "Expected client ID  %s but found %s",
            api.config["GOOGLE_CLIENT_ID"],
            resp.get("aud"),
        )
        return False

    return resp


def generate_jwt(user):
    """Generate a JWT for USER to use on routes that require
    authentication.

    """
    payload = {"email": user["email"], "name": user["name"]}
    return jwt.encode(
        payload, api.config["JWT_SECRET"], algorithm=api.config["JWT_ALGO"]
    )


def validate_jwt(encoded):
    return jwt.decode(
        encoded, api.config["JWT_SECRET"], algorithms=api.config["JWT_ALGO"]
    )


@api.route("/auth/google")
class Auth(Resource):
    @api.expect(fields=login_fields)
    def post(self):
        token = request.json()["token"]
        user = validate_google_token(token)
        if user:
            return {"token": generate_jwt(user)}

        abort(401)


@api.route("/cubs")
class Cubs(Resource):
    def get(self):
        "Get all the cubs or the ones matching the query."
        user = validate_jwt(request.headers.get("Authorization"))
        if not user:
            abort(401)

        query = dict()
        request.args.get("name")
        if name:
            query["name"] = name

        res = CUBS_DB.cubs.find(query)

        if not res:
            api.logger.info("No cubs found with query %s", str(query))
            abort(404)

        cubs = []
        for cub in res:
            cubs += cub

        return {"cubs": cubs}

    @api.expect(fields=new_cub_fields)
    def post(self):
        """Create a new cub."""
        user = validate_jwt(request.headers.get("Authorization"))
        if not user:
            api.logger.info(
                "Login failed with Authorization header %s",
                request.headers.get("Authorization"),
            )
            abort(401)

        new_cub = request.json()
        api.logger.info("Creating new cub %s", new_cub["name"])
        res = CUBS_DB.cubs.insert_one(new_cub)
        api.logger.info("Created cub %s with ID %d", res.inserted_id)

        new_cub["_id"] = res.inserted_id
        return new_cub


@api.route("/cubs/<int:id>")
class Cub(Resource):
    def get(self, id):
        """Get the cub matching the ID."""
        user = validate_jwt(request.headers.get("Authorization"))
        if not user:
            abort(401)

        cub = CUBS_DB.cubs.find_one({"_id": id})
        if not cub:
            api.logger.info("Requests cub with ID %s does not exist", id)
            abort(404)

        return cub

    def delete(self, id):
        """Delete the cub matching the ID."""
        user = validate_jwt(request.headers.get("Authorization"))
        if not user:
            abort(401)

        cub = CUBS_DB.cubs.find_one({"_id": id})
        if not cub:
            api.logger.info("Requests cub with ID %s does not exist", id)
            abort(404)

        CUBS_DB.cubs.delete_one({"_id": id})
        return cub

    @api.expect(fields=update_cub_fields)
    def patch(self, id):
        """Update the cub's document."""
        user = validate_jwt(request.headers.get("Authorization"))
        if not user:
            abort(401)

        updated_fields = request.json()

        cub = CUBS_DB.cubs.find_one({"_id": id})
        if not cub:
            api.logger.info("Requested cub with ID %s does not exist", id)
            abort(404)

        res = CUBS_DB.cubs.update_one({"_id": cub.get("_id")}, {"$set": updated_filds})

        return CUBS_DB.cubs.find_one({"_id": id})
