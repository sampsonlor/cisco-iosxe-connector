package provider

import (
	"context"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/entity/v1"
	"github.com/OmniTrustILM/go-sdk/connector/shared"
)

func definition(spec attributeSpec, value string, readOnly bool) mdl.BaseAttributeDto {
	props := *mdl.NewDataAttributeProperties(spec.name, true, true, readOnly, false, false, false)
	a := mdl.NewDataAttributeV3(spec.id, spec.name, 3, mdl.ATTRIBUTETYPE_DATA, mdl.ATTRIBUTECONTENTTYPE_STRING, props, mdl.ATTRIBUTEVERSION_V3)
	if value != "" {
		a.Content = []mdl.BaseAttributeContentDtoV3{mdl.StringAttributeContentV3AsBaseAttributeContentDtoV3(mdl.NewStringAttributeContentV3(value, mdl.ATTRIBUTECONTENTTYPE_STRING))}
	}
	v3 := mdl.DataAttributeV3AsBaseAttributeDtoV3(a)
	return mdl.BaseAttributeDtoV3AsBaseAttributeDto(&v3)
}
func (p *readOnlyProvider) Attributes(_ context.Context, kind string) ([]mdl.BaseAttributeDto, error) {
	if kind != "iosxe" {
		return nil, shared.NotFound("KIND_NOT_FOUND", "kind not found")
	}
	return []mdl.BaseAttributeDto{definition(entitySpecs[0], "", false), definition(entitySpecs[1], "", false)}, nil
}
func (p *readOnlyProvider) ValidateAttributes(_ context.Context, kind string, attrs []mdl.RequestAttribute) ([]string, error) {
	v, err := requestValue(attrs)
	if kind != "iosxe" || err != nil || !p.guard.validRequest("entityAttrs", "", v) {
		return []string{"invalid device attributes"}, nil
	}
	return nil, nil
}
func (p *readOnlyProvider) LocationAttributes(ctx context.Context, id string) ([]mdl.BaseAttributeDto, error) {
	if _, err := p.record(ctx, id); err != nil {
		return nil, err
	}
	return []mdl.BaseAttributeDto{definition(locationSpecs[0], "https", true)}, nil
}
func (p *readOnlyProvider) ValidateLocationAttributes(ctx context.Context, id string, attrs []mdl.RequestAttribute) ([]string, error) {
	if _, err := p.record(ctx, id); err != nil {
		return nil, err
	}
	v, err := requestValue(attrs)
	if err != nil || !validLocationAttrs(v) {
		return []string{"invalid HTTPS Location attributes"}, nil
	}
	return nil, nil
}
func (p *readOnlyProvider) PushCertificateAttributes(context.Context, string) ([]mdl.BaseAttributeDto, error) {
	return nil, readOnlyError()
}
func (p *readOnlyProvider) ValidatePushCertificateAttributes(context.Context, string, []mdl.RequestAttribute) ([]string, error) {
	return nil, readOnlyError()
}
func (p *readOnlyProvider) GenerateCsrAttributes(context.Context, string) ([]mdl.BaseAttributeDto, error) {
	return nil, readOnlyError()
}
func (p *readOnlyProvider) ValidateGenerateCsrAttributes(context.Context, string, []mdl.RequestAttribute) ([]string, error) {
	return nil, readOnlyError()
}
