from extensions import db
from models import AuthorizedTarget
from utils.validators import validate_domain


def create_target(owner_id: int, domain: str, description: str = "", authorized: bool = False) -> AuthorizedTarget:
    clean_domain = validate_domain(domain)
    target = AuthorizedTarget(
        domain=clean_domain,
        description=description,
        authorized=bool(authorized),
        owner_id=owner_id,
    )
    db.session.add(target)
    db.session.commit()
    return target


def update_target(target: AuthorizedTarget, **fields) -> AuthorizedTarget:
    if "domain" in fields and fields["domain"] is not None:
        target.domain = validate_domain(fields["domain"])
    if "description" in fields and fields["description"] is not None:
        target.description = fields["description"]
    if "authorized" in fields and fields["authorized"] is not None:
        target.authorized = bool(fields["authorized"])
    db.session.commit()
    return target


def delete_target(target: AuthorizedTarget) -> None:
    db.session.delete(target)
    db.session.commit()


def list_targets():
    return AuthorizedTarget.query.order_by(AuthorizedTarget.created_at.desc()).all()


def get_target(target_id: int):
    return AuthorizedTarget.query.get(target_id)


def list_target_ids_for_owner(owner_id: int):
    return [
        row.id
        for row in AuthorizedTarget.query.filter_by(owner_id=owner_id).with_entities(AuthorizedTarget.id).all()
    ]
