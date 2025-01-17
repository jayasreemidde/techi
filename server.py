from flask import Flask, request, jsonify
import face_recognition
import numpy as np
import base64
import cv2

app = Flask(__name__)

# Preload known face encodings and their labels
known_face_encodings = []
known_face_labels = []

# Function to load known faces (for simplicity, you might want to load from a database)
def load_known_faces():
    # Example: Load faces from files and generate encodings
    image = face_recognition.load_image_file("known_face.jpg")
    encoding = face_recognition.face_encodings(image)[0]
    known_face_encodings.append(encoding)
    known_face_labels.append("known_user")

# Endpoint to authenticate a face
@app.route('/authenticate', methods=['POST'])
def authenticate():
    data = request.json
    image_data = data['image']
    
    # Decode the image
    image_data = base64.b64decode(image_data)
    np_arr = np.fromstring(image_data, np.uint8)
    image = cv2.imdecode(np_arr, cv2.IMREAD_COLOR)

    # Find face encodings in the uploaded image
    face_encodings = face_recognition.face_encodings(image)
    
    if len(face_encodings) == 0:
        return jsonify({"message": "No face found"}), 400

    for face_encoding in face_encodings:
        # Check if the uploaded face matches any known faces
        matches = face_recognition.compare_faces(known_face_encodings, face_encoding)
        if True in matches:
            first_match_index = matches.index(True)
            label = known_face_labels[first_match_index]
            return jsonify({"message": "Authenticated", "user": label})

    return jsonify({"message": "Authentication failed"}), 401

if __name__ == '__main__':
    load_known_faces()
    app.run(host='0.0.0.0', port=5000)
