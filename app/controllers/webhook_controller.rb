# frozen_string_literal: true

require 'pp'

class WebhookController < ApplicationController
  def handle_webhook
    request.body.rewind
    payload_body = request.body.read
    pp params[:webhook].permit(params[:webhook].keys).to_h

    if payload_authorized?(payload_body)
      render :webhook
    else
      render json: {
        error: 'Access denied',
        status: :unauthorized
      }
    end
  end

  private

  def payload_authorized?(payload_body)
    signature = 'sha1=' + OpenSSL::HMAC.hexdigest(OpenSSL::Digest.new('sha1'), Rails.application.secrets.webhook_secret, payload_body)

    puts signature if Rails.env.development?

    Rack::Utils.secure_compare(signature, request.headers['HTTP_X_HUB_SIGNATURE'].to_s)
  end
end
