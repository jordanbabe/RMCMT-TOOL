# Django Project

This is a Django project with instructions on how to set it up and run it locally.

## Setup

1. Clone this repository to your local machine.

2. Navigate to the project directory:

    ```bash
    cd rmcmt
    ```

3. Create a virtual environment:

    ```bash
    python3 -m venv env
    ```

4. Activate the virtual environment:

    - On Windows:

    ```bash
    .\env\Scripts\activate
    ```

    - On macOS and Linux:

    ```bash
    source env/bin/activate
    ```

5. Install the project dependencies:

    ```bash
    pip install -r requirements.txt
    ```

## Running the Project

1. Navigate to the Django project directory.

2. Apply migrations:

    ```bash
    python manage.py migrate
    ```

3. Create a superuser (optional):

    ```bash
    python manage.py createsuperuser
    ```

4. Load Initial Datas:
    Load data in order:

    ```bash
    python manage.py loaddata fixtures/initial_question_type.json

    python manage.py loaddata fixtures/initial_risk_scale.json

    python manage.py loaddata fixtures/initial_questions.json

    python manage.py loaddata fixtures/initial_answers.json
    ```

5. Start the development server:

    ```bash
    python manage.py runserver
    ```

5. Open a web browser and go to `http://127.0.0.1:8000/` to view the application.

6. To access the Django admin interface, go to `http://127.0.0.1:8000/admin/` and log in with the superuser credentials created in step 3.



## Setup Using Docker

1. Navigate the project dir
2. Build the docker image
    ```bash
    sudo docker compose build
    ```
3. Run the docker image and containers
    ```bash
    sudo docker compose up
    ```
4. Migrate DB
    ```bash
    sudo docker compose run --rm django python manage.py migrate
    ```
5. Load Initial Datas
    ```bash
    sudo docker compose run --rm django python manage.py loaddata fixtures/initial_question_type.json
    
    sudo docker compose run --rm django python manage.py loaddata fixtures/initial_risk_scale.json

    sudo docker compose run --rm django python manage.py loaddata fixtures/initial_questions.json

    sudo docker compose run --rm django python manage.py loaddata fixtures/initial_answers.json
    ```
6. Create Super User
    ```bash
    sudo docker compose run --rm django python manage.py createsuperuser
    ```

7. Web Portal

<img width="1856" height="915" alt="complaince qa" src="https://github.com/user-attachments/assets/f63dcc43-29ad-4edb-a51a-cd7eb7e35ad1" />
<img width="1851" height="665" alt="risk assement marking" src="https://github.com/user-attachments/assets/12d99723-82a8-4042-a1e0-3e64d2ad4852" />
<img width="1873" height="997" alt="web app login portal" src="https://github.com/user-attachments/assets/6256e760-40c5-4e52-82b6-52e0a6436f73" />
<img width="1879" height="874" alt="risk register submit new risk" src="https://github.com/user-attachments/assets/1aafea7e-2329-475f-9772-6aa8fafc5b4f" />
