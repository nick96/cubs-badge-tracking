FROM python:3.7.2-stretch

WORKDIR /app

COPY requirements.txt /app

RUN pip install -r requirements.txt

COPY . /app

EXPOSE 8000
CMD [ “flask”, “run” ]
