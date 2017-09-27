package org.kairosdb.core.http.rest;

import com.google.inject.AbstractModule;
import com.google.inject.Scopes;

public class DeleteModule extends AbstractModule
{
	@Override
	protected void configure()
	{
		// Bind REST resource
		bind(DeleteResource.class).in(Scopes.SINGLETON);
	}
}
