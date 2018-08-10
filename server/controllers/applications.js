import { get } from 'lodash';

import models from '../models';

const { Application } = models;

export const create = async (req, res) => {

  const props = {};

  props.CreatedByUserId = req.remoteUser.id;

  props.name = get(req, 'body.name');
  props.description = get(req, 'body.description');
  props.callbackUrl = get(req, 'body.callbackUrl');

  const app = await Application.create(props);

  res.send(app.info);
}
