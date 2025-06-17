from flask import Blueprint, render_template, request, jsonify, session, current_app

main_bp = Blueprint('main', __name__)

@main_bp.route('/')
def index():
    # Move your index logic here, use current_app for services
    return render_template('index.html')

# Add other routes here, using services via current_app