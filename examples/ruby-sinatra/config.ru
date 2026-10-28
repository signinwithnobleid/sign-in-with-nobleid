# frozen_string_literal: true

# Production mode unless told otherwise: development mode would render
# exception pages that can contain request data.
ENV["APP_ENV"] ||= "production"

require_relative "app"
run App
