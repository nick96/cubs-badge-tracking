FROM python:3.7.2-stretch as build

# Install the required python packages in the builder image to that we
# don't have to have pipenv installed on the prod docker image.
RUN pip install pipenv
COPY ./Pipfile .
COPY ./Pipfile.lock .

# Install the packages to the parent system
RUN pipenv install --system --deploy --ignore-pipfile

FROM python:3.7.2-stretch as runner

# Copy the packages installed by pip in the builder image to this one.
COPY --from=build /usr/lib/python3/dist-packages .

WORKDIR /app
COPY . /app

EXPOSE 8000
CMD [ “flask”, “run” ]
